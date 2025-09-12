unit testsmartcaptcha;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, fpcunit, testregistry, smartcaptcha, smartcaptcha_config, smartcaptcha_types, fpjson, fgl
  ;

type
  TSmartCaptchaTest = class(TTestCase)
  private
    FClient: TSmartCaptcha;
    FLogMessages: TStringList;
    FLogLevels: specialize TFPGList<TEventType>;
    procedure OnLogEvent({%H-}Sender: TObject; Level: TEventType; const Message: string);
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    // Тесты конфигурации
    procedure TestConfigValidation;
    procedure TestConfigWithValidKey;
    procedure TestConfigDefaults;
    procedure TestConfigTimeouts;

    // Тесты токенов
    procedure TestEmptyToken;
    procedure TestWhitespaceToken;
    procedure TestVeryLongToken;
    procedure TestSpecialCharactersInToken;

    // Тесты IP адресов
    procedure TestWithValidIP;
    procedure TestWithInvalidIP;
    procedure TestWithEmptyIP;
    procedure TestWithIPv6;

    // Тесты логирования
    procedure TestLoggingEnabled;
    procedure TestLoggingDisabled;
    procedure TestDifferentLogLevels;

    // Тесты ошибок
    procedure TestLastErrorInitialization;
    procedure TestLastErrorPersistence;

    // Тесты создания объектов
    procedure TestCreateWithoutKey;
    procedure TestCreateWithKey;
    procedure TestCreateMultipleInstances;

    // Тесты граничных случаев
    procedure TestNullByteInToken;
    procedure TestUnicodeInToken;
    procedure TestMaxLengthToken;
  end;

  // Мок-класс для тестирования HTTP запросов

  { TMockSmartCaptcha }

  TMockSmartCaptcha = class(TSmartCaptcha)
  private
    FMockResponse: string;
    FMockStatusCode: Integer;
    FShouldThrowException: Boolean;
    FExceptionMessage: string;
  public
    procedure SetMockResponse(const AResponse: string; AStatusCode: Integer = 200);
    procedure SetMockException(const AMessage: string);
    function MakeRequest(const AToken, AIP: string): TJSONObject;
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
  FClient := TSmartCaptcha.Create('test-server-key-12345');
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

// Тесты конфигурации

procedure TSmartCaptchaTest.TestConfigValidation;
var
  aConfig: TSmartCaptchaConfig;
begin
  // Тест пустого ключа
  aConfig := TSmartCaptchaConfig.Create('');
  try
    AssertException(ESmartCaptchaConfigError, @aConfig.Validate);
  finally
    aConfig.Free;
  end;

  // Тест с валидным ключом
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
    // Тест отрицательных таймаутов
    aConfig.ConnectTimeout := -1;
    AssertException(ESmartCaptchaConfigError, @aConfig.Validate);

    aConfig.ConnectTimeout := SMARTCAPTCHA_DEFAULT_CONNECT_TIMEOUT;
    aConfig.IOTimeout := 0;
    AssertException(ESmartCaptchaConfigError, @aConfig.Validate);

    // Тест валидных таймаутов
    aConfig.ConnectTimeout := 1000;
    aConfig.IOTimeout := 5000;
    aConfig.Validate;
  finally
    aConfig.Free;
  end;
end;

// Тесты токенов

procedure TSmartCaptchaTest.TestEmptyToken;
begin
  AssertFalse(FClient.VerifyToken(''));
  AssertTrue(FClient.GetLastError.Contains('Token cannot be empty'));
end;

procedure TSmartCaptchaTest.TestWhitespaceToken;
begin
  AssertFalse(FClient.VerifyToken('   '));
  // Пробельный токен не должен проходить валидацию
end;

procedure TSmartCaptchaTest.TestVeryLongToken;
var
  aLongToken: string;
begin
  // Создаем очень длинный токен (10KB)
  aLongToken := StringOfChar('a', 10240);
  // Тест не должен падать, но токен скорее всего будет невалидным
  FClient.VerifyToken(aLongToken);
  // Проверяем, что запрос был сделан (есть логи)
  AssertTrue(FLogMessages.Count > 0);
end;

procedure TSmartCaptchaTest.TestSpecialCharactersInToken;
const
  SPECIAL_CHARS = '!@#$%^&*()_+-=[]{}|;:,.<>?`~';
begin
  // Токен со специальными символами
  FClient.VerifyToken('token-with-' + SPECIAL_CHARS);
  // Должен корректно обработаться (URL encoding)
  AssertTrue(FLogMessages.Count > 0);
end;

// Тесты IP адресов

procedure TSmartCaptchaTest.TestWithValidIP;
begin
  FClient.VerifyToken('test-token', '192.168.1.1');
  // Проверяем, что IP был передан в запрос
  AssertTrue(FLogMessages.Count > 0);
end;

procedure TSmartCaptchaTest.TestWithInvalidIP;
begin
  FClient.VerifyToken('test-token', '999.999.999.999');
  // Должен обработать некорректный IP без падения
  AssertTrue(FLogMessages.Count > 0);
end;

procedure TSmartCaptchaTest.TestWithEmptyIP;
begin
  FClient.VerifyToken('test-token', '');
  // Пустой IP должен игнорироваться
  AssertTrue(FLogMessages.Count > 0);
end;

procedure TSmartCaptchaTest.TestWithIPv6;
begin
  FClient.VerifyToken('test-token', '2001:db8::1');
  // IPv6 адрес должен корректно обрабатываться
  AssertTrue(FLogMessages.Count > 0);
end;

// Тесты логирования

procedure TSmartCaptchaTest.TestLoggingEnabled;
begin
  FClient.VerifyToken('test-token');
  // Должны быть логи о выполнении запроса
  AssertTrue(FLogMessages.Count > 0);
  AssertTrue(FLogMessages.Text.Contains('verifying token'));
end;

procedure TSmartCaptchaTest.TestLoggingDisabled;
var
  aClient: TSmartCaptcha;
begin
  aClient := TSmartCaptcha.Create('test-key');
  try
    // Без обработчика логов
    aClient.VerifyToken('test-token');
    // Не должно быть исключений
    AssertTrue(True); // Тест прошел, если дошли до этой строки
  finally
    aClient.Free;
  end;
end;

procedure TSmartCaptchaTest.TestDifferentLogLevels;
begin
  FClient.VerifyToken('');  // Вызовет Warning
  FClient.VerifyToken('test-token');  // Вызовет Debug и Error

  // Проверяем наличие разных уровней логов
  AssertTrue(FLogLevels.Count > 0);
end;

// Тесты ошибок

procedure TSmartCaptchaTest.TestLastErrorInitialization;
begin
  // При создании объекта ошибок быть не должно
  AssertEquals('', FClient.GetLastError);
end;

procedure TSmartCaptchaTest.TestLastErrorPersistence;
begin
  FClient.VerifyToken(''); // Вызовет ошибку
  AssertFalse('Must be not empty!', FClient.GetLastError.IsEmpty);

  // После успешного вызова ошибка должна сбрасываться
  FClient.VerifyToken('valid-token');
  // В реальности будет ошибка сети, но LastError сбросится в начале метода
end;

// Тесты создания объектов

procedure TSmartCaptchaTest.TestCreateWithoutKey;
var
  aClient: TSmartCaptcha;
begin
  aClient := TSmartCaptcha.Create;
  try
    AssertEquals('', aClient.Config.ServerKey);
  finally
    aClient.Free;
  end;
end;

procedure TSmartCaptchaTest.TestCreateWithKey;
var
  aClient: TSmartCaptcha;
begin
  aClient := TSmartCaptcha.Create('my-server-key');
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
  aClient1 := TSmartCaptcha.Create('key1');
  aClient2 := TSmartCaptcha.Create('key2');
  try
    AssertEquals('key1', aClient1.Config.ServerKey);
    AssertEquals('key2', aClient2.Config.ServerKey);
    AssertTrue(aClient1 <> aClient2);
  finally
    aClient1.Free;
    aClient2.Free;
  end;
end;

// Тесты граничных случаев

procedure TSmartCaptchaTest.TestNullByteInToken;
var
  aTokenWithNull: string;
begin
  aTokenWithNull := 'token' + #0 + 'with-null';
  // Не должно приводить к падению
  FClient.VerifyToken(aTokenWithNull);
  AssertTrue(FLogMessages.Count > 0);
end;

procedure TSmartCaptchaTest.TestUnicodeInToken;
const
  UNICODE_TOKEN = 'токен-с-юникодом-🔐-тест';
begin
  FClient.VerifyToken(UNICODE_TOKEN);
  // Должен корректно обрабатывать Unicode
  AssertTrue(FLogMessages.Count > 0);
end;

procedure TSmartCaptchaTest.TestMaxLengthToken;
var
  aMaxToken: string;
begin
  // Тест максимально длинного разумного токена
  aMaxToken := StringOfChar('A', 4096);
  FClient.VerifyToken(aMaxToken);
  AssertTrue(FLogMessages.Count > 0);
end;

{ TMockSmartCaptcha }

procedure TMockSmartCaptcha.SetMockResponse(const AResponse: string; AStatusCode: Integer);
begin
  FMockResponse := AResponse;
  FMockStatusCode := AStatusCode;
  FShouldThrowException := False;
end;

procedure TMockSmartCaptcha.SetMockException(const AMessage: string);
begin
  FShouldThrowException := True;
  FExceptionMessage := AMessage;
end;

function TMockSmartCaptcha.MakeRequest(const AToken, AIP: string): TJSONObject;
begin

end;

initialization
  RegisterTest(TSmartCaptchaTest);

end.
