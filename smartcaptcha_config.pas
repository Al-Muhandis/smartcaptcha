unit smartcaptcha_config;

{$mode ObjFPC}{$H+}

interface

uses
  SysUtils, smartcaptcha_types
  ;

type

  { TSmartCaptchaConfig }

  TSmartCaptchaConfig = class
  private
    FServerKey: string;
    FBaseURL: string;
    FConnectTimeout: Integer;
    FIOTimeout: Integer;
  public
    constructor Create(const AServerKey: string);  
    constructor Create;
    procedure Validate;
    property ServerKey: String read FServerKey write FServerKey;
    property BaseURL: String read FBaseURL;
    property ConnectTimeout: Integer read FConnectTimeout write FConnectTimeout;
    property IOTimeout: Integer read FIOTimeout write FIOTimeout;
  end;

implementation

constructor TSmartCaptchaConfig.Create(const AServerKey: string);
begin
  FServerKey := AServerKey;
  Create;
end;

constructor TSmartCaptchaConfig.Create;
begin
  FBaseURL := SMARTCAPTCHA_DEFAULT_URL;
  FConnectTimeout := SMARTCAPTCHA_DEFAULT_CONNECT_TIMEOUT;
  FIOTimeout := SMARTCAPTCHA_DEFAULT_IO_TIMEOUT;
end;

procedure TSmartCaptchaConfig.Validate;
begin
  if FServerKey.IsEmpty then
    raise ESmartCaptchaConfigError.Create('ServerKey cannot be empty');
  if FBaseURL.IsEmpty then
    raise ESmartCaptchaConfigError.Create('BaseURL cannot be empty');
  if FConnectTimeout <= 0 then
    raise ESmartCaptchaConfigError.Create('ConnectTimeout must be positive');
  if FIOTimeout <= 0 then
    raise ESmartCaptchaConfigError.Create('IOTimeout must be positive');
end;

end.
