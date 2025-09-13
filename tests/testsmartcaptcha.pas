unit testsmartcaptcha;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, fpcunit, testregistry, smartcaptcha, smartcaptcha_config, smartcaptcha_types, fpjson, fgl,
  mocksmartcaptcha
  ;

type
  TSmartCaptchaTest = class(TTestCase)
  private
    FClient: TMockSmartCaptcha;
    FLogMessages: TStringList;
    FLogLevels: specialize TFPGList<TEventType>;
    procedure OnLogEvent({%H-}Sender: TObject; Level: TEventType; const Message: string);
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    // Config tests
    procedure TestConfigValidation;
    procedure TestConfigWithValidKey;
    procedure TestConfigDefaults;
    procedure TestConfigTimeouts;

    // Token tests
    procedure TestEmptyToken;
    procedure TestWhitespaceToken;
    procedure TestVeryLongToken;
    procedure TestSpecialCharactersInToken;

    // IP tests
    procedure TestWithValidIP;
    procedure TestWithInvalidIP;
    procedure TestWithEmptyIP;
    procedure TestWithIPv6;

    // Logging tests
    procedure TestLoggingEnabled;
    procedure TestLoggingDisabled;
    procedure TestDifferentLogLevels;

    // Error tests
    procedure TestLastErrorInitialization;
    procedure TestLastErrorPersistence;

    // Object creation tests
    procedure TestCreateWithoutKey;
    procedure TestCreateWithKey;
    procedure TestCreateMultipleInstances;

    // Edge cases tests
    procedure TestNullByteInToken;
    procedure TestUnicodeInToken;
    procedure TestMaxLengthToken;

    // Suscess responses tests
    procedure TestSuccessfulVerification;
    procedure TestSuccessfulVerificationWithIP;
    procedure TestRequestParametersCapture;

    // Various server error tests
    procedure TestServerFailureResponse;
    procedure TestServerFailureWithCustomMessage;
    procedure TestHTTPErrorResponses;
    procedure TestEmptyServerResponse;
    procedure TestInvalidJSONResponse;
    procedure TestMissingStatusField;
    procedure TestNetworkException;

    // Query sequence tests
    procedure TestMultipleSuccessfulRequests;
    procedure TestMixedResponses;
    procedure TestRequestSequence;

    // Tests of ready-made mock methods
    procedure TestSetupSuccessResponse;
    procedure TestSetupFailureResponse;
    procedure TestSetupNetworkErrorResponse;
    procedure TestSetupInvalidJsonResponse;

    // Mock Response reset Tests
    procedure TestResetMockResponses;
    procedure TestMockResponsesExhaustion;

    // Tests of various status codes
    procedure TestDifferentHTTPStatusCodes;

    // Edge cases tests for JSON responses
    procedure TestJSONResponseEdgeCases;
  end;

implementation

{ TSmartCaptchaTest }

procedure TSmartCaptchaTest.OnLogEvent(Sender: TObject; Level: TEventType; const Message: string);
begin
  FLogMessages.Add(Message);
  FLogLevels.Add(Level);
end;

procedure TSmartCaptchaTest.SetUp;
begin
  FClient := TMockSmartCaptcha.Create('test-server-key-12345');
  FLogMessages := TStringList.Create;
  FLogLevels := specialize TFPGList<TEventType>.Create;
  FClient.OnLog := @OnLogEvent;
end;

procedure TSmartCaptchaTest.TearDown;
begin
  FClient.Free;
  FLogMessages.Free;
  FLogLevels.Free;
end;

procedure TSmartCaptchaTest.TestConfigValidation;
var
  aConfig: TSmartCaptchaConfig;
begin
  aConfig := TSmartCaptchaConfig.Create('');
  try
    AssertException(ESmartCaptchaConfigError, @aConfig.Validate);
  finally
    aConfig.Free;
  end;

  aConfig := TSmartCaptchaConfig.Create('valid-key');
  try
    aConfig.Validate;
  finally
    aConfig.Free;
  end;
end;

procedure TSmartCaptchaTest.TestConfigWithValidKey;
var
  aConfig: TSmartCaptchaConfig;
begin
  aConfig := TSmartCaptchaConfig.Create('test-key-123');
  try
    AssertEquals('test-key-123', aConfig.ServerKey);
    AssertEquals(SMARTCAPTCHA_DEFAULT_URL, aConfig.BaseURL);
    AssertEquals(SMARTCAPTCHA_DEFAULT_CONNECT_TIMEOUT, aConfig.ConnectTimeout);
    AssertEquals(SMARTCAPTCHA_DEFAULT_IO_TIMEOUT, aConfig.IOTimeout);
  finally
    aConfig.Free;
  end;
end;

procedure TSmartCaptchaTest.TestConfigDefaults;
var
  aConfig: TSmartCaptchaConfig;
begin
  aConfig := TSmartCaptchaConfig.Create;
  try
    AssertEquals('', aConfig.ServerKey);
    AssertEquals(SMARTCAPTCHA_DEFAULT_URL, aConfig.BaseURL);
    AssertEquals(SMARTCAPTCHA_DEFAULT_CONNECT_TIMEOUT, aConfig.ConnectTimeout);
    AssertEquals(SMARTCAPTCHA_DEFAULT_IO_TIMEOUT, aConfig.IOTimeout);
  finally
    aConfig.Free;
  end;
end;

procedure TSmartCaptchaTest.TestConfigTimeouts;
var
  aConfig: TSmartCaptchaConfig;
begin
  aConfig := TSmartCaptchaConfig.Create('test-key');
  try
    aConfig.ConnectTimeout := -1;
    AssertException(ESmartCaptchaConfigError, @aConfig.Validate);

    aConfig.ConnectTimeout := SMARTCAPTCHA_DEFAULT_CONNECT_TIMEOUT;
    aConfig.IOTimeout := 0;
    AssertException(ESmartCaptchaConfigError, @aConfig.Validate);

    aConfig.ConnectTimeout := 1000;
    aConfig.IOTimeout := 5000;
    aConfig.Validate;
  finally
    aConfig.Free;
  end;
end;

procedure TSmartCaptchaTest.TestEmptyToken;
begin
  AssertFalse(FClient.VerifyToken(''));
  AssertTrue(FClient.GetLastError.Contains('Token cannot be empty'));
end;

procedure TSmartCaptchaTest.TestWhitespaceToken;
begin
  AssertFalse(FClient.VerifyToken('   '));
  AssertTrue(FClient.GetLastError.Contains('Token cannot be empty'));
end;

procedure TSmartCaptchaTest.TestVeryLongToken;
var
  aLongToken: string;
begin
  aLongToken := StringOfChar('a', 10240);
  FClient.SetupSuccessResponse;
  AssertTrue(FClient.VerifyToken(aLongToken));
  AssertTrue(FLogMessages.Count > 0);
end;

procedure TSmartCaptchaTest.TestSpecialCharactersInToken;
const
  SPECIAL_CHARS = '!@#$%^&*()_+-=[]{}|;:,.<>?`~';
var
  aTokenWithSpecialChars: string;
begin
  aTokenWithSpecialChars := 'token-with-' + SPECIAL_CHARS;
  FClient.SetupSuccessResponse;
  FClient.EnableRequestCapture;

  AssertTrue(FClient.VerifyToken(aTokenWithSpecialChars));
  AssertEquals(aTokenWithSpecialChars, FClient.LastToken);
end;

procedure TSmartCaptchaTest.TestWithValidIP;
begin
  FClient.SetupSuccessResponse;
  FClient.EnableRequestCapture;

  AssertTrue(FClient.VerifyToken('test-token', '192.168.1.1'));
  AssertEquals('test-token', FClient.LastToken);
  AssertEquals('192.168.1.1', FClient.LastIP);
end;

procedure TSmartCaptchaTest.TestWithInvalidIP;
begin
  FClient.SetupSuccessResponse;
  FClient.EnableRequestCapture;

  AssertTrue(FClient.VerifyToken('test-token', '999.999.999.999'));
  AssertEquals('999.999.999.999', FClient.LastIP);
end;

procedure TSmartCaptchaTest.TestWithEmptyIP;
begin
  FClient.SetupSuccessResponse;
  FClient.EnableRequestCapture;

  AssertTrue(FClient.VerifyToken('test-token', ''));
  AssertEquals('', FClient.LastIP);
end;

procedure TSmartCaptchaTest.TestWithIPv6;
begin
  FClient.SetupSuccessResponse;
  FClient.EnableRequestCapture;

  AssertTrue(FClient.VerifyToken('test-token', '2001:db8::1'));
  AssertEquals('2001:db8::1', FClient.LastIP);
end;

procedure TSmartCaptchaTest.TestLoggingEnabled;
begin
  FClient.SetupSuccessResponse;
  AssertTrue(FClient.VerifyToken('test-token'));

  AssertTrue(FLogMessages.Count > 0);
  AssertTrue(FLogMessages.Text.Contains('verifying token'));
end;

procedure TSmartCaptchaTest.TestLoggingDisabled;
var
  aClient: TMockSmartCaptcha;
begin
  aClient := TMockSmartCaptcha.Create('test-key');
  try
    aClient.SetupSuccessResponse;
    AssertTrue(aClient.VerifyToken('test-token'));
  finally
    aClient.Free;
  end;
end;

procedure TSmartCaptchaTest.TestDifferentLogLevels;
begin
  FClient.VerifyToken('');  // Warning level
  FClient.SetupSuccessResponse;
  FClient.VerifyToken('test-token');  // Debug and Info levels

  AssertTrue(FLogLevels.Count >= 2);
  AssertTrue(FLogLevels.IndexOf(etWarning) >= 0);
  AssertTrue(FLogLevels.IndexOf(etDebug) >= 0);
end;

procedure TSmartCaptchaTest.TestLastErrorInitialization;
begin
  AssertEquals('', FClient.GetLastError);
end;

procedure TSmartCaptchaTest.TestLastErrorPersistence;
begin
  FClient.VerifyToken('');
  AssertFalse(FClient.GetLastError.IsEmpty);

  FClient.SetupSuccessResponse;
  FClient.VerifyToken('valid-token');
end;

procedure TSmartCaptchaTest.TestCreateWithoutKey;
var
  aClient: TMockSmartCaptcha;
begin
  aClient := TMockSmartCaptcha.Create;
  try
    AssertEquals('', aClient.Config.ServerKey);
  finally
    aClient.Free;
  end;
end;

procedure TSmartCaptchaTest.TestCreateWithKey;
var
  aClient: TMockSmartCaptcha;
begin
  aClient := TMockSmartCaptcha.Create('my-server-key');
  try
    AssertEquals('my-server-key', aClient.Config.ServerKey);
  finally
    aClient.Free;
  end;
end;

procedure TSmartCaptchaTest.TestCreateMultipleInstances;
var
  aClient1, aClient2: TSmartCaptcha;
begin
  aClient1 := TMockSmartCaptcha.Create('key1');
  aClient2 := TMockSmartCaptcha.Create('key2');
  try
    AssertEquals('key1', aClient1.Config.ServerKey);
    AssertEquals('key2', aClient2.Config.ServerKey);
    AssertTrue(aClient1 <> aClient2);
  finally
    aClient1.Free;
    aClient2.Free;
  end;
end;

procedure TSmartCaptchaTest.TestNullByteInToken;
var
  aTokenWithNull: string;
begin
  aTokenWithNull := 'token' + #0 + 'with-null';
  FClient.SetupSuccessResponse;
  FClient.EnableRequestCapture;

  AssertTrue(FClient.VerifyToken(aTokenWithNull));
  AssertEquals(aTokenWithNull, FClient.LastToken);
end;

procedure TSmartCaptchaTest.TestUnicodeInToken;
const
  UNICODE_TOKEN = 'токен-с-юникодом-🔐-тест';
begin
  FClient.SetupSuccessResponse;
  FClient.EnableRequestCapture;

  AssertTrue(FClient.VerifyToken(UNICODE_TOKEN));
  AssertEquals(UNICODE_TOKEN, FClient.LastToken);
end;

procedure TSmartCaptchaTest.TestMaxLengthToken;
var
  aMaxToken: string;
begin
  aMaxToken := StringOfChar('A', 4096);
  FClient.SetupSuccessResponse;

  AssertTrue(FClient.VerifyToken(aMaxToken));
  AssertTrue(FLogMessages.Count > 0);
end;

procedure TSmartCaptchaTest.TestSuccessfulVerification;
begin
  FClient.SetupSuccessResponse;

  AssertTrue(FClient.VerifyToken('valid-token-123'));
  AssertEquals('', FClient.GetLastError);

  AssertTrue(FLogMessages.Text.Contains('verification successful'));
end;

procedure TSmartCaptchaTest.TestSuccessfulVerificationWithIP;
begin
  FClient.SetupSuccessResponse;
  FClient.EnableRequestCapture;

  AssertTrue(FClient.VerifyToken('valid-token', '203.0.113.42'));
  AssertEquals('valid-token', FClient.LastToken);
  AssertEquals('203.0.113.42', FClient.LastIP);
end;

procedure TSmartCaptchaTest.TestRequestParametersCapture;
begin
  FClient.SetupSuccessResponse;
  FClient.EnableRequestCapture;

  FClient.VerifyToken('captured-token', '10.0.0.1');

  AssertEquals('captured-token', FClient.LastToken);
  AssertEquals('10.0.0.1', FClient.LastIP);
end;

procedure TSmartCaptchaTest.TestServerFailureResponse;
begin
  FClient.SetupFailureResponse('invalid-token');

  AssertFalse(FClient.VerifyToken('bad-token'));
  AssertTrue(FClient.GetLastError.Contains('invalid-token'));

  AssertTrue(FLogMessages.Text.Contains('verification failed'));
end;

procedure TSmartCaptchaTest.TestServerFailureWithCustomMessage;
const
  CUSTOM_ERROR = 'Token expired or malformed';
begin
  FClient.SetupFailureResponse(CUSTOM_ERROR);

  AssertFalse(FClient.VerifyToken('expired-token'));
  AssertEquals(CUSTOM_ERROR, FClient.GetLastError);
end;

procedure TSmartCaptchaTest.TestHTTPErrorResponses;
begin
  FClient.AddMockResponse(404, 'Not Found');
  AssertFalse(FClient.VerifyToken('some-token'));
  AssertTrue(FClient.GetLastError.Contains('HTTP error 404'));

  FClient.ResetMockResponses;

  FClient.AddMockResponse(500, 'Internal Server Error');
  AssertFalse(FClient.VerifyToken('some-token'));
  AssertTrue(FClient.GetLastError.Contains('HTTP error 500'));

  FClient.ResetMockResponses;

  FClient.AddMockResponse(403, 'Forbidden');
  AssertFalse(FClient.VerifyToken('some-token'));
  AssertTrue(FClient.GetLastError.Contains('HTTP error 403'));
end;

procedure TSmartCaptchaTest.TestEmptyServerResponse;
begin
  FClient.AddMockResponse(200, '');

  AssertFalse(FClient.VerifyToken('some-token'));
  AssertTrue(FClient.GetLastError.Contains('Empty response'));
end;

procedure TSmartCaptchaTest.TestInvalidJSONResponse;
begin
  FClient.SetupInvalidJsonResponse;

  AssertFalse(FClient.VerifyToken('some-token'));
  AssertTrue(FClient.GetLastError.Contains('JSON parse error'));
end;

procedure TSmartCaptchaTest.TestMissingStatusField;
begin
  FClient.AddMockResponse(200, '{"message": "no status field"}');

  AssertFalse(FClient.VerifyToken('some-token'));
  AssertTrue(FClient.GetLastError.Contains('Missing "status" field'));
end;

procedure TSmartCaptchaTest.TestNetworkException;
begin
  FClient.SetupNetworkErrorResponse;

  AssertFalse(FClient.VerifyToken('some-token'));
  AssertEquals('Connection timeout', FClient.GetLastError);
end;

procedure TSmartCaptchaTest.TestMultipleSuccessfulRequests;
begin
  FClient.SetupSuccessResponse;
  FClient.SetupSuccessResponse;
  FClient.SetupSuccessResponse;

  AssertTrue(FClient.VerifyToken('token1'));
  AssertTrue(FClient.VerifyToken('token2'));
  AssertTrue(FClient.VerifyToken('token3'));
end;

procedure TSmartCaptchaTest.TestMixedResponses;
begin
  FClient.SetupSuccessResponse;
  FClient.SetupFailureResponse('invalid');
  FClient.SetupSuccessResponse;

  AssertTrue(FClient.VerifyToken('good-token1'));
  AssertFalse(FClient.VerifyToken('bad-token'));
  AssertTrue(FClient.VerifyToken('good-token2'));
end;

procedure TSmartCaptchaTest.TestRequestSequence;
begin
  FClient.AddMockResponse(200, '{"status": "ok"}');
  FClient.AddMockResponse(400, 'Bad Request');
  FClient.AddMockResponse(200, '{"status": "failed", "message": "rate-limited"}');
  FClient.EnableRequestCapture;

  AssertTrue(FClient.VerifyToken('token1', '1.1.1.1'));
  AssertEquals('token1', FClient.LastToken);
  AssertEquals('1.1.1.1', FClient.LastIP);

  AssertFalse(FClient.VerifyToken('token2', '2.2.2.2'));
  AssertEquals('token2', FClient.LastToken);
  AssertEquals('2.2.2.2', FClient.LastIP);

  AssertFalse(FClient.VerifyToken('token3'));
  AssertEquals('token3', FClient.LastToken);
  AssertTrue(FClient.GetLastError.Contains('rate-limited'));
end;

procedure TSmartCaptchaTest.TestSetupSuccessResponse;
begin
  FClient.SetupSuccessResponse;
  AssertTrue(FClient.VerifyToken('any-token'));
  AssertEquals('', FClient.GetLastError);
end;

procedure TSmartCaptchaTest.TestSetupFailureResponse;
begin
  FClient.SetupFailureResponse;
  AssertFalse(FClient.VerifyToken('any-token'));
  AssertTrue(FClient.GetLastError.Contains('invalid-token'));

  FClient.ResetMockResponses;
  FClient.SetupFailureResponse('custom-error-message');
  AssertFalse(FClient.VerifyToken('any-token'));
  AssertEquals('custom-error-message', FClient.GetLastError);
end;

procedure TSmartCaptchaTest.TestSetupNetworkErrorResponse;
begin
  FClient.SetupNetworkErrorResponse;
  AssertFalse(FClient.VerifyToken('any-token'));
  AssertEquals('Connection timeout', FClient.GetLastError);
end;

procedure TSmartCaptchaTest.TestSetupInvalidJsonResponse;
begin
  FClient.SetupInvalidJsonResponse;
  AssertFalse(FClient.VerifyToken('any-token'));
  AssertTrue(FClient.GetLastError.Contains('JSON parse error'));
end;

procedure TSmartCaptchaTest.TestResetMockResponses;
begin
  FClient.SetupSuccessResponse;
  FClient.SetupFailureResponse;

  FClient.ResetMockResponses;

  AssertFalse(FClient.VerifyToken('any-token'));
  AssertTrue(FClient.GetLastError.Contains('No mock response configured'));
end;

procedure TSmartCaptchaTest.TestMockResponsesExhaustion;
begin
  FClient.SetupSuccessResponse;

  AssertTrue(FClient.VerifyToken('token1'));

  AssertFalse(FClient.VerifyToken('token2'));
  AssertTrue(FClient.GetLastError.Contains('No mock response configured'));
end;

procedure TSmartCaptchaTest.TestDifferentHTTPStatusCodes;
const
  HTTP_CODES: array[0..6] of Integer = (400, 401, 403, 404, 429, 500, 503);
var
  i: Integer;
begin
  for i := Low(HTTP_CODES) to High(HTTP_CODES) do
  begin
    FClient.ResetMockResponses;
    FClient.AddMockResponse(HTTP_CODES[i], Format('Error %d', [HTTP_CODES[i]]));

    AssertFalse(FClient.VerifyToken('test-token'));
    AssertTrue(FClient.GetLastError.Contains(Format('HTTP error %d', [HTTP_CODES[i]])));
  end;
end;

procedure TSmartCaptchaTest.TestJSONResponseEdgeCases;
begin
  FClient.ResetMockResponses;
  FClient.AddMockResponse(200, '{"status": "ok", "extra_field": "value", "timestamp": 1234567890}');
  AssertTrue(FClient.VerifyToken('test-token'));

  FClient.ResetMockResponses;
  FClient.AddMockResponse(200, '{"status": true}');
  AssertFalse(FClient.VerifyToken('test-token'));

  FClient.ResetMockResponses;
  FClient.AddMockResponse(200, '{"response": {"status": "ok"}}');
  AssertFalse(FClient.VerifyToken('test-token'));
  AssertTrue(FClient.GetLastError.Contains('Missing "status" field'));

  FClient.ResetMockResponses;
  FClient.AddMockResponse(200, '{}');
  AssertFalse(FClient.VerifyToken('test-token'));
  AssertTrue(FClient.GetLastError.Contains('Missing "status" field'));

  FClient.ResetMockResponses;
  FClient.AddMockResponse(200, '{"status": "ok", "data": "' + StringOfChar('x', 10000) + '"}');
  AssertTrue(FClient.VerifyToken('test-token'));
end;

initialization
  RegisterTest(TSmartCaptchaTest);

end.
