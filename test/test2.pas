unit test2;

interface

type
 x = int;
 y = int;

type
  foo = int;
  bar = ^int;
  xyz = string;
  baz = boolean;
  a = foo;
  b = bar;
  x = xyz;
  y = baz;
  testrec = record
    a: integer;
  end;

const pi: Float = 5;

var x: Integer;
var x: Integer;
x: Integer;
x: Integer;

procedure bla(x: Integer; foo: String); overload;

implementation

procedure bla(x: Integer; foo: String);
var thev: Integer;
const bla: Blub = 5;
begin
end;

procedure blub(x: Integer; foo: String);
const quirks: Kra = 5;
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
const quirks: Kra = 5;
const bla: testrec = 5;
begin
  if testrec.foo shl testrec.a then begin end;
  while cool do begin end;
  if (3 - 4) < 5 then
    if yes then begin
      blub();
    end else begin
    end;
end;

end.
