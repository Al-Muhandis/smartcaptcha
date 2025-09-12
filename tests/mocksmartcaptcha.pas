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

    // Методы для настройки mock поведения
    procedure AddMockResponse(StatusCode: Integer; const Body: string);
    procedure AddMockException(const ExceptionMessage: string);
    procedure ResetMockResponses;

    // Методы для проверки последнего запроса
    procedure EnableRequestCapture;
    property LastToken: string read FLastToken;
    property LastIP: string read FLastIP;

    // Готовые mock ответы
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
  MockResp: TMockResponse;
begin
  Result := nil;
  FLastError := '';

  // Захватываем параметры запроса если включено
  if FCaptureLastRequest then
  begin
    FLastToken := AToken;
    FLastIP := AIP;
  end;

  // Проверяем, есть ли настроенные mock ответы
  if (FCurrentResponseIndex >= Length(FMockResponses)) then
  begin
    FLastError := 'No mock response configured';
    DoLog(etError, 'Mock: %s', [FLastError]);
    Exit;
  end;

  MockResp := FMockResponses[FCurrentResponseIndex];
  Inc(FCurrentResponseIndex);

  DoLog(etDebug, 'Mock: returning response %d with status %d',
    [FCurrentResponseIndex, MockResp.StatusCode]);

  // Симулируем исключение если нужно
  if MockResp.ShouldThrow then
  begin
    FLastError := MockResp.ExceptionMessage;
    DoLog(etError, 'Mock: simulating exception: %s', [FLastError]);
    Exit;
  end;

  // Симулируем HTTP ошибку
  if MockResp.StatusCode <> 200 then
  begin
    FLastError := Format('HTTP error %d: %s', [MockResp.StatusCode, MockResp.Body]);
    DoLog(etError, 'Mock: simulating HTTP error: %s', [FLastError]);
    Exit;
  end;

  // Симулируем пустой ответ
  if MockResp.Body.IsEmpty then
  begin
    FLastError := 'Empty response from server';
    DoLog(etError, 'Mock: %s', [FLastError]);
    Exit;
  end;

  // Пытаемся парсить JSON
  try
    Result := GetJSON(MockResp.Body) as TJSONObject;
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
  Resp: TMockResponse;
begin
  Resp.StatusCode := StatusCode;
  Resp.Body := Body;
  Resp.ShouldThrow := False;
  Resp.ExceptionMessage := '';

  SetLength(FMockResponses, Length(FMockResponses) + 1);
  FMockResponses[High(FMockResponses)] := Resp;
end;

procedure TMockSmartCaptcha.AddMockException(const ExceptionMessage: string);
var
  Resp: TMockResponse;
begin
  Resp.StatusCode := 0;
  Resp.Body := '';
  Resp.ShouldThrow := True;
  Resp.ExceptionMessage := ExceptionMessage;

  SetLength(FMockResponses, Length(FMockResponses) + 1);
  FMockResponses[High(FMockResponses)] := Resp;
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
