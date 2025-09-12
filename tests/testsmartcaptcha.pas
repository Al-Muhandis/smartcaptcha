unit testsmartcaptcha;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, fpcunit, testregistry, smartcaptcha, smartcaptcha_config
  ;

type
  TSmartCaptchaTest = class(TTestCase)
  private
    FClient: TSmartCaptcha;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestConfigValidation;
    procedure TestEmptyToken;
  end;

implementation

uses
  smartcaptcha_types
  ;

procedure TSmartCaptchaTest.SetUp;
begin
  FClient := TSmartCaptcha.Create('test-key');
end;

procedure TSmartCaptchaTest.TearDown;
begin
  FClient.Free;
end;

procedure TSmartCaptchaTest.TestConfigValidation;
var
  aConfig: TSmartCaptchaConfig;
begin
  aConfig:=TSmartCaptchaConfig.Create('');
  try
    AssertException(ESmartCaptchaConfigError, @aConfig.Validate);
  finally
    aConfig.Free;
  end;
end;

procedure TSmartCaptchaTest.TestEmptyToken;
begin
  AssertFalse(FClient.VerifyToken(''));
end;

// Другие тесты...

initialization
  RegisterTest(TSmartCaptchaTest);

end.
