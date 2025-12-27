unit uSecureRandom;

interface

uses
  System.SysUtils;

type
  TSecureRandom = record
  public
    { Fill Buffer with cryptographically secure random bytes }
    class procedure GetBytes(var Buffer; Size: Integer); static;

    { Return a byte array of secure random bytes }
    class function Bytes(Size: Integer): TBytes; static;

    { Convenience: random integers }
    class function UInt32: Cardinal; static;
    class function UInt64: UInt64; static;

    { Bias-safe integer in [0, MaxExclusive) }
    class function IntRange(MaxExclusive: Integer): Integer; static;

    { Convenience: encodings }
    class function Hex(BytesCount: Integer): string; static;
    class function Base64(BytesCount: Integer): string; static;
  end;

implementation

uses
  System.Classes,
  System.NetEncoding

{$IF Defined(MSWINDOWS)}
  , Winapi.Windows;

type
  NTSTATUS = LongInt;

const
  BCRYPT_USE_SYSTEM_PREFERRED_RNG = $00000002;

function BCryptGenRandom(hAlgorithm: Pointer; pbBuffer: PByte; cbBuffer: ULONG; dwFlags: ULONG): NTSTATUS; stdcall;
  external 'bcrypt.dll' name 'BCryptGenRandom';
{$ELSE}
 ;
{$ENDIF}

{$IF Defined(MACOS) or Defined(IOS)}
uses
  Macapi.Security;
{$ENDIF}

{$IF Defined(POSIX) and not (Defined(MACOS) or Defined(IOS))}
uses
  System.IOUtils;
{$ENDIF}

procedure Fail(const Msg: string);
begin
  raise EInvalidOperation.Create(Msg);
end;

function BytesToHexLower(const B: TBytes): string;
const
  Hex: array[0..15] of Char = ('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f');
var
  I, J: Integer;
  V: Byte;
begin
  SetLength(Result, Length(B) * 2);
  J := 1;
  for I := 0 to High(B) do
  begin
    V := B[I];
    Result[J] := Hex[V shr 4];
    Inc(J);
    Result[J] := Hex[V and $0F];
    Inc(J);
  end;
end;

class procedure TSecureRandom.GetBytes(var Buffer; Size: Integer);
{$IF Defined(MSWINDOWS)}
var
  Status: NTSTATUS;
begin
  if Size <= 0 then Exit;
  Status := BCryptGenRandom(nil, PByte(@Buffer), ULONG(Size), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if Status <> 0 then
    Fail(Format('BCryptGenRandom failed (NTSTATUS=%d)', [Status]));
end;
{$ELSEIF Defined(MACOS) or Defined(IOS)}
var
  Err: Integer;
begin
  if Size <= 0 then Exit;
  Err := SecRandomCopyBytes(kSecRandomDefault, Size, @Buffer);
  if Err <> 0 then
    Fail(Format('SecRandomCopyBytes failed (err=%d)', [Err]));
end;
{$ELSEIF Defined(POSIX)}
var
  FS: TFileStream;
begin
  if Size <= 0 then Exit;

  // Linux / Android: kernel CSPRNG via /dev/urandom
  FS := TFileStream.Create('/dev/urandom', fmOpenRead or fmShareDenyNone);
  try
    if FS.Read(Buffer, Size) <> Size then
      Fail('Failed to read enough bytes from /dev/urandom');
  finally
    FS.Free;
  end;
end;
{$ELSE}
begin
  Fail('Secure RNG not implemented for this platform/compiler.');
end;
{$ENDIF}

class function TSecureRandom.Bytes(Size: Integer): TBytes;
begin
  if Size < 0 then
    raise EArgumentOutOfRangeException.Create('Size must be >= 0');

  SetLength(Result, Size);
  if Size > 0 then
    GetBytes(Result[0], Size);
end;

class function TSecureRandom.UInt32: Cardinal;
begin
  GetBytes(Result, SizeOf(Result));
end;

class function TSecureRandom.UInt64: UInt64;
begin
  GetBytes(Result, SizeOf(Result));
end;

class function TSecureRandom.IntRange(MaxExclusive: Integer): Integer;
var
  R, Limit: Cardinal;
begin
  if MaxExclusive <= 0 then
    raise EArgumentOutOfRangeException.Create('MaxExclusive must be > 0');

  // Avoid modulo bias
  Limit := High(Cardinal) - (High(Cardinal) mod Cardinal(MaxExclusive));

  repeat
    R := UInt32;
  until R < Limit;

  Result := Integer(R mod Cardinal(MaxExclusive));
end;

class function TSecureRandom.Hex(BytesCount: Integer): string;
var
  B: TBytes;
begin
  B := Bytes(BytesCount);
  Result := BytesToHexLower(B);
end;

class function TSecureRandom.Base64(BytesCount: Integer): string;
var
  B: TBytes;
begin
  B := Bytes(BytesCount);
  Result := TNetEncoding.Base64.EncodeBytesToString(B);
end;

end.

