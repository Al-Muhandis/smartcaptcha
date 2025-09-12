{ This file was automatically created by Lazarus. Do not edit!
  This source is only used to compile and install the package.
 }

unit smartcaptcha_rt;

{$warn 5023 off : no warning about unused units}
interface

uses
  smartcaptcha, LazarusPackageIntf;

implementation

procedure Register;
begin
end;

initialization
  RegisterPackage('smartcaptcha_rt', @Register);
end.
