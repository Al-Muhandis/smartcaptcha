unit mocksmartcaptcha;

{$mode ObjFPC}{$H+}

interface

uses
  SysUtils, fpjson, smartcaptcha
  ;

type
  TMockResponse = record
    StatusCode: Integer;
    Body: string;
    ShouldThrow: Boolean;
    ExceptionMessage: string;
  end;

  { TMockSmartCaptcha }

  TMockSmartCaptcha = class(TSmartCaptcha)
  private
    FMockResponses: array of TMockResponse;
    FCurrentResponseIndex: Integer;
    FCaptureLastRequest: Boolean;
    FLastToken: string;
    FLastIP: string;
  protected
    function MakeRequest(const AToken, AIP: string): TJSONObject; override;
  public                                      
    constructor Create;
    constructor Create(const AServerKey: string);

    // Methods for configuring mock behavior
    procedure AddMockResponse(StatusCode: Integer; const Body: string);
    procedure AddMockException(const ExceptionMessage: string);
    procedure ResetMockResponses;

    // Methods for checking the last request
    procedure EnableRequestCapture;
    property LastToken: string read FLastToken;
    property LastIP: string read FLastIP;

    // Ready-made mock responses
    procedure SetupSuccessResponse;
    procedure SetupFailureResponse(const ErrorMessage: string = 'invalid-token');
    procedure SetupNetworkErrorResponse;
    procedure SetupInvalidJsonResponse;
  end;

implementation

uses
  Classes
  ;

{ TMockSmartCaptcha }

constructor TMockSmartCaptcha.Create(const AServerKey: string);
begin
  inherited Create(AServerKey);
  FCurrentResponseIndex := 0;
  FCaptureLastRequest := False;
end;

function TMockSmartCaptcha.MakeRequest(const AToken, AIP: string): TJSONObject;
var
  aMockResp: TMockResponse;
begin
  Result := nil;
  FLastError := '';

  // Capturing the request parameters if enabled
  if FCaptureLastRequest then
  begin
    FLastToken := AToken;
    FLastIP := AIP;
  end;

  // Checking if there are configured mock responses.
  if (FCurrentResponseIndex >= Length(FMockResponses)) then
  begin
    FLastError := 'No mock response configured';
    DoLog(etError, 'Mock: %s', [FLastError]);
    Exit;
  end;

  aMockResp := FMockResponses[FCurrentResponseIndex];
  Inc(FCurrentResponseIndex);

  DoLog(etDebug, 'Mock: returning response %d with status %d',
    [FCurrentResponseIndex, aMockResp.StatusCode]);

  // Simulate an exception if necessary
  if aMockResp.ShouldThrow then
  begin
    FLastError := aMockResp.ExceptionMessage;
    DoLog(etError, 'Mock: simulating exception: %s', [FLastError]);
    Exit;
  end;

  // Simulating an HTTP error
  if aMockResp.StatusCode <> 200 then
  begin
    FLastError := Format('HTTP error %d: %s', [aMockResp.StatusCode, aMockResp.Body]);
    DoLog(etError, 'Mock: simulating HTTP error: %s', [FLastError]);
    Exit;
  end;

  // Simulate an empty response
  if aMockResp.Body.IsEmpty then
  begin
    FLastError := 'Empty response from server';
    DoLog(etError, 'Mock: %s', [FLastError]);
    Exit;
  end;

  // Try to parse JSON
  try
    Result := GetJSON(aMockResp.Body) as TJSONObject;
    DoLog(etDebug, 'Mock: successfully parsed JSON response');
  except
    on E: Exception do
    begin
      FLastError := Format('JSON parse error: %s', [E.Message]);
      DoLog(etError, 'Mock: JSON error: %s', [FLastError]);
    end;
  end;
end;

constructor TMockSmartCaptcha.Create;
begin
  inherited Create;
  FCurrentResponseIndex := 0;
  FCaptureLastRequest := False;
end;

procedure TMockSmartCaptcha.AddMockResponse(StatusCode: Integer; const Body: string);
var
  aResp: TMockResponse;
begin
  aResp.StatusCode := StatusCode;
  aResp.Body := Body;
  aResp.ShouldThrow := False;
  aResp.ExceptionMessage := '';

  SetLength(FMockResponses, Length(FMockResponses) + 1);
  FMockResponses[High(FMockResponses)] := aResp;
end;

procedure TMockSmartCaptcha.AddMockException(const ExceptionMessage: string);
var
  aResp: TMockResponse;
begin
  aResp.StatusCode := 0;
  aResp.Body := '';
  aResp.ShouldThrow := True;
  aResp.ExceptionMessage := ExceptionMessage;

  SetLength(FMockResponses, Length(FMockResponses) + 1);
  FMockResponses[High(FMockResponses)] := aResp;
end;

procedure TMockSmartCaptcha.ResetMockResponses;
begin
  SetLength(FMockResponses, 0);
  FCurrentResponseIndex := 0;
  FLastToken := '';
  FLastIP := '';
end;

procedure TMockSmartCaptcha.EnableRequestCapture;
begin
  FCaptureLastRequest := True;
end;

procedure TMockSmartCaptcha.SetupSuccessResponse;
begin
  AddMockResponse(200, '{"status": "ok"}');
end;

procedure TMockSmartCaptcha.SetupFailureResponse(const ErrorMessage: string);
begin
  AddMockResponse(200, Format('{"status": "failed", "message": "%s"}', [ErrorMessage]));
end;

procedure TMockSmartCaptcha.SetupNetworkErrorResponse;
begin
  AddMockException('Connection timeout');
end;

procedure TMockSmartCaptcha.SetupInvalidJsonResponse;
begin
  AddMockResponse(200, 'invalid json{');
end;

end.
