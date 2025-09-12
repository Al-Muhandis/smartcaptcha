program test_gui;

{$mode objfpc}{$H+}

uses
  Interfaces, Forms, GuiTestRunner, testsmartcaptcha
  ;

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TGuiTestRunner, TestRunner);
  Application.Run;
end.

