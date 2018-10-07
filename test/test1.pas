unit test1;

interface

type
 Tx = int;
 Ty = int;

type
 foo = int;
 bar = ^int;
 xyz = string;
 baz = boolean;
 a = foo;
 b = bar;
 Tx = xyz;
 Ty = baz;
 testrec = record
 end;

const
  pi: Float = 3;
  true: Integer = 4;
{$IFDEF defineCool}
  cool: Integer = 4;
{$ELSE}
  cool: Integer = 42;
{$ENDIF}

{$IFDEF defineX}
var x: Integer;
var x: Integer;
var x: Integer;
var x: Integer;
{$ENDIF}
var x: Integer;

procedure bla(x: Integer; foo: String); overload;

implementation

procedure bla(foo: String);
var thev: Integer;
const bla: Blub = 1;
begin
    x := 1;
end;

procedure blub(x: Integer; foo: String);
const quirks: Kra = 1;
begin
  if x then begin
    x := 3
  end;
  while true do begin
    foo;
    bar();
  end;
  if bla then if blub then begin end else begin end;
end;

function fn(x: Integer; foo: String): Ret;
const quirks: Kra = 1;
begin
  if x shl 3 then begin end;
  while cool do begin end;
  if (3 + 4) < 5 then
    if yes then begin
      blub();
    end else begin
    end;
end;

end.
