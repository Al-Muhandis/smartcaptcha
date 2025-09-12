unit smartcaptcha_types;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, eventlog, sysutils
  ;

type
  TSmartCaptchaLogEvent = procedure(Sender: TObject; Level: TEventType; const Message: string) of object;

  ESmartCaptchaError = class(Exception);
  ESmartCaptchaNetworkError = class(ESmartCaptchaError);
  ESmartCaptchaParseError = class(ESmartCaptchaError);
  ESmartCaptchaConfigError = class(ESmartCaptchaError);

const
  SMARTCAPTCHA_DEFAULT_URL = 'https://smartcaptcha.yandexcloud.net/validate';
  SMARTCAPTCHA_DEFAULT_CONNECT_TIMEOUT = 5000;
  SMARTCAPTCHA_DEFAULT_IO_TIMEOUT = 10000;

implementation

end.
