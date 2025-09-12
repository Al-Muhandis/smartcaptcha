unit smartcaptcha;

{$mode ObjFPC}{$H+}

interface

uses
  SysUtils, eventlog
  ;

type

  TSmartCaptcha = class;

  TLogNotify = procedure (aSmartCaptcha: TSmartCaptcha; aEvent: TEventType; const aMessage: String) of Object;

  { TSmartCaptcha }

  TSmartCaptcha = class
  private
    FLogger: TEventLog;
    FOnLog: TLogNotify;
    procedure Log(aEvent: TEventType; const aMessage: String);
    procedure Log(aEvent: TEventType; const aMessage: String; aArgs: array of const);
  public
    function check_captcha(const aSmartCaptchaServerKey, aToken: string; const aIP: String = ''): Boolean;
    property Logger: TEventLog read FLogger write FLogger;
    property OnLog: TLogNotify read FOnLog write FOnLog;
  end;

implementation

uses
  fphttpclient, fpjson
  ;

{ TSmartCaptcha }

procedure TSmartCaptcha.Log(aEvent: TEventType; const aMessage: String);
begin
  if Assigned(FLogger) then
    FLogger.Log(aEvent, aMessage);
  if Assigned(FOnLog) then
    FOnLog(Self, aEvent, aMessage);
end;

procedure TSmartCaptcha.Log(aEvent: TEventType; const aMessage: String; aArgs: array of const);
begin
  if Assigned(FLogger) then
    FLogger.Log(aEvent, aMessage, aArgs);
  if Assigned(FOnLog) then
    FOnLog(Self, aEvent, Format(aMessage, aArgs));
end;

function TSmartCaptcha.check_captcha(const aSmartCaptchaServerKey, aToken: string; const aIP: String): Boolean;
var
  aHTTP: TFPHTTPClient;
  args: string;
  aServer_output: string;
  aHttpcode: integer;
  aResp: TJSONData;
begin
  aHTTP := TFPHTTPClient.Create(nil);
  try
    args := 'secret=' + aSmartCaptchaServerKey + '&token=' + aToken;
    if not aIP.IsEmpty then
      args+='&ip='+aIP;
    try
      aServer_output := aHTTP.Get('https://smartcaptcha.yandexcloud.net/validate?' + args);
      aHttpcode := aHTTP.ResponseStatusCode;

      if aHttpcode <> 200 then begin
        Log(etError, 'Allow access due to an error: code=%d; message=%s', [aHttpcode, aServer_output]);
        Result := true;
        Exit;
      end;

      aResp := GetJSON(aServer_output);
      try
        Result := aResp.FindPath('status').AsString = 'ok';
      finally
        aResp.Free;
      end;
    except
      on E: Exception do
        Log(etError, 'Error during processing response: %s', [E.Message]);
    end;
  finally
    aHTTP.Free;
  end;
end;

end.

