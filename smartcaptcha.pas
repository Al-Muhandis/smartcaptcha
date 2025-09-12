unit smartcaptcha;

{$mode ObjFPC}{$H+}
{$interfaces CORBA}

interface

uses
  SysUtils, eventlog, smartcaptcha_types, smartcaptcha_config, fpjson
  ;

type
  ISmartCaptchaClient = interface
  ['{B3DBA86E-8936-4632-9A8B-50E1A0EF5372}']
    function VerifyToken(const AToken: string; const AIP: String = ''): Boolean;
    function GetLastError: string;
  end;

  TSmartCaptcha = class;

  TLogNotify = procedure (aSmartCaptcha: TSmartCaptcha; aEvent: TEventType; const aMessage: String) of Object;

  { TSmartCaptcha }

  TSmartCaptcha = class(TObject, ISmartCaptchaClient)
  private
    FConfig: TSmartCaptchaConfig;
    FLogger: TEventLog;
    FOnLog: TSmartCaptchaLogEvent;
    FSkipNon200: Boolean;
    function ValidateToken(const AToken: string): Boolean;
  protected                                                      
    FLastError: string;                                                                                
    procedure DoLog(aLevel: TEventType; const aMessage: string); overload;
    procedure DoLog(aLevel: TEventType; const aMessage: string; const aArgs: array of const); overload;
    function MakeRequest(const AToken, AIP: string): TJSONObject; virtual;
  public
    constructor Create;
    constructor Create(const AServerKey: string); overload;
    destructor Destroy; override;

    function VerifyToken(const aToken: string; const aIP: String = ''): Boolean;
    function GetLastError: string;

    property Config: TSmartCaptchaConfig read FConfig;
    property Logger: TEventLog read FLogger write FLogger;
    property OnLog: TSmartCaptchaLogEvent read FOnLog write FOnLog;
    property SkipNon200: Boolean read FSkipNon200 write FSkipNon200;
  end;

implementation

uses
  fphttpclient, Classes
  ;

{ TSmartCaptcha }

procedure TSmartCaptcha.DoLog(aLevel: TEventType; const aMessage: string);
begin
  if Assigned(FLogger) then
    FLogger.Log(ALevel, aMessage);
  if Assigned(FOnLog) then
    FOnLog(Self, ALevel, aMessage);
end;

procedure TSmartCaptcha.DoLog(aLevel: TEventType; const aMessage: string; const aArgs: array of const);
begin
  DoLog(aLevel, Format(aMessage, AArgs));
end;

function TSmartCaptcha.MakeRequest(const AToken, AIP: string): TJSONObject;
var
  aHTTP: TFPHTTPClient;
  aPostData: TStringList;
  aResponse: string;
  aResponseCode: Integer;
begin
  Result := nil;
  FLastError := '';

  aHTTP := TFPHTTPClient.Create(nil);
  try
    aHTTP.ConnectTimeout := FConfig.ConnectTimeout;
    aHTTP.IOTimeout := FConfig.IOTimeout;

    aPostData := TStringList.Create;
    try
      aPostData.AddPair('secret', EncodeURLElement(FConfig.ServerKey));
      aPostData.AddPair('token', EncodeURLElement(aToken));
      if not aIP.IsEmpty then
        aPostData.AddPair('ip', aIP);
      aHTTP.AddHeader('User-Agent', 'YandexSmartCaptcha-FPC/1.0');
      try
        aResponse := aHTTP.FormPost(FConfig.BaseURL, aPostData);
        aResponseCode := aHTTP.ResponseStatusCode;

        DoLog(etDebug, 'SmartCaptcha response: HTTP %d, body length: %d', [aResponseCode, Length(aResponse)]);

        if aResponseCode <> 200 then begin
          FLastError := Format('HTTP error %d: %s', [aResponseCode, aResponse]);
          DoLog(etError, 'SmartCaptcha HTTP error: %s', [FLastError]);
          Exit;
        end;

        if aResponse.IsEmpty then begin
          FLastError := 'Empty response from server';
          DoLog(etError, 'SmartCaptcha: %s', [FLastError]);
          Exit;
        end;

        try
          Result := GetJSON(aResponse) as TJSONObject;
        except
          on E: Exception do
          begin
            FLastError := Format('JSON parse error: %s', [E.Message]);
            DoLog(etError, 'SmartCaptcha JSON error: %s', [FLastError]);
          end;
        end;

      except
        on E: Exception do
          DoLog(etError, 'SmartCaptcha request error: %s', [E.Message]);
      end;

    finally
      aPostData.Free;
    end;
  finally
    aHTTP.Free;
  end;
end;

function TSmartCaptcha.ValidateToken(const AToken: string): Boolean;
begin
  Result := not AToken.Trim.IsEmpty;
  if not Result then
    FLastError := 'Token cannot be empty or whitespace-only';
end;

constructor TSmartCaptcha.Create;
begin
  inherited Create;
  FConfig:=TSmartCaptchaConfig.Create;
end;

constructor TSmartCaptcha.Create(const AServerKey: string);
begin
  FConfig:=TSmartCaptchaConfig.Create(AServerKey);
  inherited Create;
end;

destructor TSmartCaptcha.Destroy;
begin
  FConfig.Free;
  inherited Destroy;
end;

function TSmartCaptcha.VerifyToken(const aToken: string; const aIP: String): Boolean;
var
  aResponseObj: TJSONObject;
  aStatusNode: TJSONData;
  aMessageNode: TJSONData;
begin
  Result := False;
  FLastError := '';

  if not ValidateToken(AToken) then
  begin
    DoLog(etWarning, 'SmartCaptcha: %s', [FLastError]);
    Exit;
  end;

  try
    FConfig.Validate;
  except
    on E: ESmartCaptchaConfigError do
    begin
      FLastError := Format('Configuration error: %s', [E.Message]);
      DoLog(etError, 'SmartCaptcha: %s', [FLastError]);
      Exit;
    end;
  end;

  DoLog(etDebug, 'SmartCaptcha: verifying token (length: %d)', [Length(AToken)]);

  aResponseObj := MakeRequest(aToken, aIP);
  if not Assigned(aResponseObj) then
    Exit; // Ошибка уже залогирована в MakeRequest

  try
    aStatusNode := aResponseObj.FindPath('status');
    if not Assigned(aStatusNode) then
    begin
      FLastError := 'Missing "status" field in response';
      DoLog(etError, 'SmartCaptcha: %s', [FLastError]);
      Exit;
    end;

    Result := aStatusNode.AsString = 'ok';

    if not Result then
    begin
      // Попытаемся получить сообщение об ошибке
      aMessageNode := aResponseObj.FindPath('message');
      if Assigned(aMessageNode) then
        FLastError := aMessageNode.AsString
      else
        FLastError := Format('Verification failed: status = "%s"', [aStatusNode.AsString]);

      DoLog(etWarning, 'SmartCaptcha verification failed: %s', [FLastError]);
    end else
    begin
      DoLog(etInfo, 'SmartCaptcha: verification successful');
    end;

  finally
    aResponseObj.Free;
  end;
end;

function TSmartCaptcha.GetLastError: string;
begin
  Result:=FLastError;
end;

end.

