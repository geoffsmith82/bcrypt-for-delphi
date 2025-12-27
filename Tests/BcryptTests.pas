unit BcryptTests;

interface

uses
  DUnitX.TestFramework,
  System.SysUtils,
  System.Diagnostics,
  System.TimeSpan,
  Bcrypt
 ;

type
	TBCryptTests = class(TObject)
	public
		procedure SpeedTests;
		function GetCompilerOptions: string;
  private
    class function SelfTest: Boolean;
		class function SelfTestA: Boolean; //known test vectors
		class function SelfTestB: Boolean; //BSD's base64 encoder/decoder
		class function SelfTestC: Boolean; //unicode strings in UTF8
		class function SelfTestD: Boolean; //different length passwords
		class function SelfTestE: Boolean; //salt rng
		class function SelfTestF: Boolean; //correctbatteryhorsestapler
		class function SelfTestG: Boolean; //check that we support up to 72 characters
		class function SelfTestH: Boolean; //check that we don't limit our passwords to 256 characters (as OpenBSD did)
		class function SelfTestI: Boolean; //check that we use unicode compatible composition (NFKC) on passwords
		class function SelfTestJ: Boolean; //check that composed and decomposed strings both validate to the same
		class function SelfTestK: Boolean; //SASLprep rules for passwords
		class function SelfTestL: Boolean; //Test prehashing a password (sha256 -> base64)
	public
		//These are just too darn slow (as they should be) for continuous testing
	//	procedure SelfTest;

	published

		[Test] procedure SelfTestA_KnownTestVectors; //known test vectors
		[Test] procedure SelfTestB_Base64EncoderDecoder; //BSD's base64 encoder/decoder
		[Test] procedure SelfTestC_UnicodeStrings; //unicode strings in UTF8
		[Test] procedure SelfTestD_VariableLengthPasswords; //different length passwords
		[Test] procedure SelfTestE_SaltRNG; //salt rng
		[Test] procedure SelfTestF_CorrectBattery; //correctbatteryhorsestapler
	  [Test] procedure SelfTestG_PasswordLength; //check that we support up to 72 characters
		[Test] procedure SelfTestH_OpenBSDLengthBug; //check that we don't limit our passwords to 256 characters (as OpenBSD did)
		[Test] procedure SelfTestI_UnicodeCompatibleComposition; //check that we apply KC normalization (NIST SP 800-63B)
		[Test] procedure SelfTestJ_NormalizedPasswordsMatch; //
		[Test] procedure SelfTestK_SASLprep; //
		[Test] procedure SelfTestL_Prehash;

		[Test] procedure Test_ParseHashString; //How well we handle past, present, and future versioning strings

		[Test] procedure TestEnhancedHash;
		[Test] procedure TestParseEnhancedHash;

		procedure Benchmark;
		[Test] procedure Test_ManualSystem;
	end;


const
	TestVectors: array[1..20, 1..3] of string = (
			('',                                   '$2a$06$DCq7YPn5Rq63x1Lad4cll.',    '$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.'),
			('',                                   '$2a$08$HqWuK6/Ng6sg9gQzbLrgb.',    '$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye'),
			('',                                   '$2a$10$k1wbIrmNyFAPwPVPSVa/ze',    '$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW'),
			('',                                   '$2a$12$k42ZFHFWqBp3vWli.nIn8u',    '$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO'),
			('a',                                  '$2a$06$m0CrhHm10qJ3lXRY.5zDGO',    '$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe'),
			('a',                                  '$2a$08$cfcvVd2aQ8CMvoMpP2EBfe',    '$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V.'),
			('a',                                  '$2a$10$k87L/MF28Q673VKh8/cPi.',    '$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u'),
			('a',                                  '$2a$12$8NJH3LsPrANStV6XtBakCe',    '$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS'),
			('abc',                                '$2a$06$If6bvum7DFjUnE9p2uDeDu',    '$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i'),
			('abc',                                '$2a$08$Ro0CUfOqk6cXEKf3dyaM7O',    '$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm'),
			('abc',                                '$2a$10$WvvTPHKwdBJ3uk0Z37EMR.',    '$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi'),
			('abc',                                '$2a$12$EXRkfkdmXn2gzds2SSitu.',    '$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q'),
			('abcdefghijklmnopqrstuvwxyz',         '$2a$06$.rCVZVOThsIa97pEDOxvGu',    '$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC'),
			('abcdefghijklmnopqrstuvwxyz',         '$2a$08$aTsUwsyowQuzRrDqFflhge',    '$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz.'),
			('abcdefghijklmnopqrstuvwxyz',         '$2a$10$fVH8e28OQRj9tqiDXs1e1u',    '$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq'),
			('abcdefghijklmnopqrstuvwxyz',         '$2a$12$D4G5f18o7aMMfwasBL7Gpu',    '$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG'),
			('~!@#$%^&*()      ~!@#$%^&*()PNBFRD', '$2a$06$fPIsBO8qRqkjj273rfaOI.',    '$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO'),
			('~!@#$%^&*()      ~!@#$%^&*()PNBFRD', '$2a$08$Eq2r4G/76Wv39MzSX262hu',    '$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW'),
			('~!@#$%^&*()      ~!@#$%^&*()PNBFRD', '$2a$10$LgfYWkbzEvQ4JakH7rOvHe',    '$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS'),
			('~!@#$%^&*()      ~!@#$%^&*()PNBFRD', '$2a$12$WApznUOJfkEGSmYRfnkrPO',    '$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC')
	);


implementation

{ TBCryptTests }

class function TBCryptTests.SelfTest: Boolean;
begin
	Result := True;

	Result := Result and SelfTestA;  //known test vectors
	Result := Result and SelfTestB;  //the base64 encoder/decoder
	Result := Result and SelfTestC;  //unicode strings
	Result := Result and SelfTestD;  //different length passwords
	Result := Result and SelfTestE;  //salt RNG
	Result := Result and SelfTestF;  //example of correct horse battery staple
	Result := Result and SelfTestG;  //72 byte key length (71characters + 1 null = 72)
	Result := Result and SelfTestH;  //check out handling of strings longer than 255 characters
	Result := Result and SelfTestI;  //check that we use unicode compatible composition (NFKC) on passwords
	Result := Result and SelfTestJ;  //check that composed and decomposed strings both validate to the same
	Result := Result and SelfTestK;  //SASLprep rules for passwords

	Result := Result and SelfTestL;  //Test prehashing a password (sha256 -> base64)
end;

class function TBCryptTests.SelfTestA: Boolean;
var
	i: Integer;

	procedure t(const password: UnicodeString; const HashSalt: string; const ExpectedHashString: string);
	var
		version: string;
		cost: Integer;
		salt: TBytes;
		isEnhanced: Boolean;
		hash: TBytes;
		actualHashString: string;
	begin
		//Extract "$2a$06$If6bvum7DFjUnE9p2uDeDu" rounds and base64 salt from the HashSalt
		if not TBCrypt.TryParseHashString(HashSalt, {out}version, {out}cost, {out}salt, {out}isEnhanced) then
			raise Exception.Create('bcrypt self-test failed: invalid versionsalt "'+HashSalt+'"');

		hash := TBCrypt.HashPassword(password, salt, cost);
		actualHashString := TBCrypt.FormatPasswordHashForBsd(version, cost, salt, hash);

		if actualHashString <> ExpectedHashString then
			raise Exception.CreateFmt('bcrypt self-test failed. Password: "%s". Actual hash "%s". Expected hash: "%s"', [password, actualHashString, ExpectedHashString]);
	end;

begin
	for i := Low(TestVectors) to High(TestVectors) do
	begin
		t(TestVectors[i,1], TestVectors[i,2], TestVectors[i,3] );
	end;

	Result := True;
end;

class function TBCryptTests.SelfTestB: Boolean;
var
	i: Integer;
	salt: string;
	encoded: string;
	data: TBytes;
	recoded: string;
const
	SSelfTestFailed = 'BSDBase64 encoder self-test failed';
begin
	for i := Low(TestVectors) to High(TestVectors) do
	begin
		salt := TestVectors[i,2];

		encoded := Copy(salt, 8, 22); //salt is always 22 characters

		data := TBCrypt.BsdBase64Decode(encoded);

		recoded := TBCrypt.BsdBase64Encode(data, Length(data));
		if (recoded <> encoded) then
			raise Exception.Create(SSelfTestFailed);
	end;

	Result := True;
end;


class function TBCryptTests.SelfTestC: Boolean;
var
	s: UnicodeString;
	hash: string;
	rehashNeeded: Boolean;
const
	n: UnicodeString=''; //n=nothing.
			//Work around bug in Delphi compiler when building widestrings
			//http://stackoverflow.com/a/7031942/12597
begin
	{
		We test that the it doesn't choke on international characters
		This was a bug in a version of bcrypt somewhere, that we do not intend to duplicate
	}
	s := n+#$03C0+#$03C0+#$03C0+#$03C0+#$03C0+#$03C0+#$03C0+#$03C0; //U+03C0: Greek Small Letter Pi
	hash := TBCrypt.HashPassword(s);
	if not TBCrypt.CheckPassword(s, hash, {out}rehashNeeded) then
		raise Exception.Create('Failed to validate unicode string "'+s+'"');


	s := n+#$03C0+#$03C0+#$03C0+#$03C0+#$03C0+#$03C0+#$03C0+#$03C0; //U+03C0: Greek Small Letter Pi
	hash := TBCrypt.HashPassword(s);
	if not TBCrypt.CheckPassword(s, hash, {out}rehashNeeded) then
		raise Exception.Create('Failed to validate unicode string "'+s+'"');

	Result := True;
end;


class function TBCryptTests.SelfTestD: Boolean;
var
	i: Integer;
	password: string;
	hash: string;
begin
	for i := 0 to 56 do
	begin
		password := Copy('The quick brown fox jumped over the lazy dog then sat on a log', 1, i);
		hash := TBCrypt.HashPassword(password, 4);
		if (hash = '') then
			raise Exception.Create('hash creation failed');
	end;

	Result := True;
end;

class function TBCryptTests.SelfTestE: Boolean;
var
	salt: TBytes;
begin
	{
		Ensure that the salt generator creates salt, and it is of the correct length.
	}
	salt := TBCrypt.GenerateSalt;
	if Length(salt) <> BCRYPT_SALT_LEN then
		raise Exception.Create('BCrypt selftest failed; invalid salt length');

	Result := True;
end;

class function TBCryptTests.SelfTestF: Boolean;
var
	rehashNeeded: Boolean;
begin
	{
		Validate a known password hash
	}
	//DebugOutput('SAMPLING ON');
	Result := TBCrypt.CheckPassword('correctbatteryhorsestapler', '$2a$12$mACnM5lzNigHMaf7O1py1O3vlf6.BA8k8x3IoJ.Tq3IB/2e7g61Km', {out}rehashNeeded);
	//DebugOutput('SAMPLING OFF');
end;

class function TBCryptTests.SelfTestG: Boolean;
var
	s55, s56, s57: TBytes;
	s70, s71, s72, s73, s74: TBytes;
	sCopy: TBytes;
	salt: TBytes;

	function BytesEqual(const data1, data2: array of Byte): Boolean;
	begin
		Result := True;

		if Length(data1) <> Length(data2) then
		begin
			Result := False;
			Exit;
		end;

		if Length(data1) = 0 then
			Exit;

		Result := CompareMem(@data1[0], @data2[0], Length(data1))
   end;
const
	testPassword = 'The quick brown fox jumped over the lazy dog then sat on a log. The sixth sick';
	//                                                                   56^               ^72
begin
	Result := True;

	salt := TBCrypt.GenerateSalt;

	s55 := TBCrypt.HashPassword(Copy(testPassword, 1, 55), salt, 4);
	s56 := TBCrypt.HashPassword(Copy(testPassword, 1, 56), salt, 4);
	s57 := TBCrypt.HashPassword(Copy(testPassword, 1, 57), salt, 4);

	//First make sure that we can generate the same hash twice with the same password and salt
	sCopy := TBCrypt.HashPassword(Copy(testPassword, 1, 55), salt, 4);
	if not BytesEqual(s55, sCopy) then
		Result := False;

	//The old limit was 56 byte (55 characters + 1 null terminator). Make sure that we can at least handle 57
	if BytesEqual(s55, s56) then
		Result := False;
	if BytesEqual(s56, s57) then
		Result := False;

	//Finally, do the same test around the 72 character limit. If you specify more than 71 characters, it is cut off
	//20161025: Change to match what OpenBSD does: they cut off the byte array - null terminator and all - after 72 bytes
	s70 := TBCrypt.HashPassword(Copy(testPassword, 1, 70), salt, 4);
	s71 := TBCrypt.HashPassword(Copy(testPassword, 1, 71), salt, 4);
	s72 := TBCrypt.HashPassword(Copy(testPassword, 1, 72), salt, 4);
	s73 := TBCrypt.HashPassword(Copy(testPassword, 1, 73), salt, 4);
	s74 := TBCrypt.HashPassword(Copy(testPassword, 1, 74), salt, 4);

	if BytesEqual(s70, s71) then //we should have still had room
		Result := False;

	if BytesEqual(s71, s72) then //the 72 character version has no room for the null terminator anymore, so it's also going to be different
		Result := False;

	if not BytesEqual(s72, s73) then //we should have stopped at 72 characters
		Result := False;
	if not BytesEqual(s72, s74) then //definitely don't overflow into 74
		Result := False;
end;

class function TBCryptTests.SelfTestH: Boolean;
var
	szPassword: string;
	rehashNeeded: Boolean;
begin
{
	A bug was discovered in the OpenBSD implemenation of bcrypt in February of 2014

		http://undeadly.org/cgi?action=article&sid=20140224132743
		http://marc.info/?l=openbsd-misc&m=139320023202696

	They were storing the length of their strings in an unsigned char (i.e. 0..255)
	If a password was longer than 255 characters, it would overflow and wrap at 255.

	They fixed their bug, and decided that everyone should use a new version string (2b).

	Delphi doesn't have this problem, because Delphi does strings correctly (length prefixed, null terminated, reference counted)
}
	szPassword := StringOfChar('a', 260);

	Result := TBCrypt.CheckPassword(szPassword, '$2a$04$QqpSfI8JYX8HSxNwW5yx8Ohp12sNboonE6e5jfnGZ0fD4ZZwQkOOK', {out}rehashNeeded);
end;

class function TBCryptTests.SelfTestI: Boolean;
var
	password: String;
	utf8: TBytes;
const
	n: String=''; //n=nothing.
			//Work around bug in Delphi compiler when building widestrings
			//http://stackoverflow.com/a/7031942/12597
begin
	{
		Before: A + ¨ + fi + n
				A:  U+0041
				¨:  U+0308 Combining Diaeresis
				fi: U+FB01 Latin Small Ligature Fi
				n:  U+006E

		Normalized:  Ä + f + i + n
				Ä:  U+00C4  Latin Capital Letter A with Diaeresis
				f:  U+0066
				i:  U+0069
				n:  U+006E

		Final UTF-8:
				Ä:  0xC3 0x84
				f:  0x66
				i:  0x69
				n:  0x6E
				\0: 0x00
	}
	password := n + 'A' + #$0308 + #$FB01 + 'n';

	utf8 := TBCrypt.PasswordStringPrep(password);

	{
		0xC3 0x84 0x66 0x69 0x6E 0x00
	}
	Result := (Length(utf8) = 6);
	Result := Result and (utf8[0] = $c3);
	Result := Result and (utf8[1] = $84);
	Result := Result and (utf8[2] = $66);
	Result := Result and (utf8[3] = $69);
	Result := Result and (utf8[4] = $6e);
	Result := Result and (utf8[5] = $00); //we do include the null terminator
end;

class function TBCryptTests.SelfTestJ: Boolean;
var
	password1: UnicodeString;
	password2: UnicodeString;
	hash: string;
	passwordRehashNeeded: Boolean;
const
	n: UnicodeString=''; //n=nothing.
			//Work around bug in Delphi compiler when building widestrings
			//http://stackoverflow.com/a/7031942/12597
begin
	{
		There are four Unicode normalization schemes:

			NFC	Composition
			NFD	Decomposition
			NFKC	Compatible Composition   <--- the one we use
			NFKD	Compatible Decomposition

		NIST Special Publication 800-63-3B (Digital Authentication Guideline - Authentication and Lifecycle Management)
			says that passwords should have unicode normalization KC or KD applied.

		RFC7613 (SASLprep) specifies the use of NFKC
			https://tools.ietf.org/html/rfc7613
			 Preparation, Enforcement, and Comparison of Internationalized Strings Representing Usernames and Passwords

		Original
				A:  U+0041
				¨:  U+0308 Combining Diaeresis
				fi: U+FB01 Latin Small Ligature Fi
				n:  U+006E

		Normalized:  Ä + f + i + n
				Ä:  U+00C4  Latin Capital Letter A with Diaeresis
				f:  U+0066
				i:  U+0069
				n:  U+006E
	}
	password1 := n + 'A' + #$0308 + #$FB01 + 'n';
	password2 := n + #$00C4 + 'f' + 'i' + 'n';

	hash := TBCrypt.HashPassword(password1, 4);

	Result := TBCrypt.CheckPassword(password2, hash, {out}passwordRehashNeeded);
end;

class function TBCryptTests.SelfTestK: Boolean;
var
	pass: UnicodeString;

	function CheckUtf8(const s: UnicodeString; Expected: array of Byte): Boolean;
	var
		data: TBytes;
	begin
		Result := False;

		data := TBCrypt.PasswordStringPrep(s);

		if Length(data) <> Length(Expected) then
			Exit;

		if not CompareMem(@data[0], @Expected[0], Length(data)) then
			Exit;

		Result := True;
	end;

begin
	{
		1. Width-Mapping Rule: Fullwidth and halfwidth characters MUST NOT be mapped to their decomposition mappings
			(see Unicode Standard Annex #11 [UAX11](https://tools.ietf.org/html/rfc7613#ref-UAX11)).
	}

	Result := True;

	{
		Fullwidth "Test"

			U+FF34  FULLWIDTH LATIN CAPITAL LETTER T   UTF8 0xEF 0xBC 0xB4
			U+FF45  FULLWIDTH LATIN SMALL LETTER   e   UTF8 0xEF 0xBD 0x85
			U+FF53  FULLWIDTH LATIN SMALL LETTER   s   UTF8 0xEF 0xBD 0x93
			U+FF54  FULLWIDTH LATIN SMALL LETTER   t   UTF8 0xEF 0xBD 0x94
	}
	//pass := #$ff34 + #$ff45 + #$ff53 + #$ff54;
	//if not CheckUtf8(pass, [$ef, $bc, $b4, $ef, $bd, $85, $bd, $93, $ef, $bd, $94, 0]) then Result := False;


	{
		Halfwidth
			U+FFC3  HALFWIDTH HANGUL LETTER AE         UTF8 0xEF 0xBF 0x83
	}
	//pass := #$ffc3;
	//if not CheckUtf8(pass, [$ef, $bf, $83, 0]) then Result := False;


	{
		2.  Additional Mapping Rule: Any instances of non-ASCII space MUST be mapped to ASCII space (U+0020);
			 a non-ASCII space is any Unicode code point having a Unicode general category of "Zs"
			 (with the  exception of U+0020).

			U+0020	SPACE
			U+00A0	NO-BREAK SPACE
			U+1680	OGHAM SPACE MARK
			U+2000	EN QUAD
			U+2001	EM QUAD
			U+2002	EN SPACE
			U+2003	EM SPACE
			U+2004	THREE-PER-EM SPACE
			U+2005	FOUR-PER-EM SPACE
			U+2006	SIX-PER-EM SPACE
			U+2007	FIGURE SPACE
			U+2008	PUNCTUATION SPACE
			U+2009	THIN SPACE
			U+200A	HAIR SPACE
			U+202F	NARROW NO-BREAK SPACE
			U+205F	MEDIUM MATHEMATICAL SPACE
			U+3000	IDEOGRAPHIC SPACE
	}
	pass := #$0020;
	if not CheckUtf8(pass, [$20, 0]) then Result := False;
	pass := #$00A0;
	if not CheckUtf8(pass, [$20, 0]) then Result := False;
	pass := #$2000;
	if not CheckUtf8(pass, [$20, 0]) then Result := False;
end;

class function TBCryptTests.SelfTestL: Boolean;
var
	actual: string;
	data: TBytes;
begin
	{
		From passlib.hash.bcrypt_sha256 - BCrypt+SHA256
		https://passlib.readthedocs.io/en/stable/lib/passlib.hash.bcrypt_sha256.html


		Input: "password"
		Expected: "XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg="
	}

	//utf8 version of "password"
	SetLength(data, 8);
	data[0] := Ord('p');
	data[1] := Ord('a');
	data[2] := Ord('s');
	data[3] := Ord('s');
	data[4] := Ord('w');
	data[5] := Ord('o');
	data[6] := Ord('r');
	data[7] := Ord('d');

	actual := TBCrypt.HashBytes256(data);

	Result := ('XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg=' = actual);
end;



procedure TBCryptTests.Benchmark;
var
    cost: Integer;
    durationMS: Double;
    elapsedTimeStopWatch : TStopwatch;
    elapsed : TTimeSpan;
begin
    if not FindCmdLineSwitch('SlowUnitTests', ['/', '-'], True) then
    begin
        Status('Very slow test. Specify -SlowUnitTests to include');
        Exit;
    end;


    Status('Cost factor	Duration (ms)');

    cost := 4; //the minimum supported bcrypt cost

    DebugOutput('SAMPLING ON');
    while (cost <= 16{31}) do
    begin
        elapsedTimeStopWatch := TStopwatch.StartNew;
        TBCrypt.HashPassword('benchmark', cost);
        elapsed := elapsedTimeStopWatch.Elapsed;

        durationMS := elapsed.TotalMilliseconds;

        Status(Format('%d	%.4f', [cost, durationMS]));

        Inc(cost);

        if durationMS > 15000 then
            Break;
    end;
    DebugOutput('SAMPLING OFF');

    Status(Self.GetCompilerOptions);
end;

function TBCryptTests.GetCompilerOptions: string;

	procedure Add(s: string);
	begin
		if Result <> '' then
			Result := Result+#13#10;

		Result := Result + s;
	end;

begin
	Result := '';

(*
	Other than for certain debugging situations, you should never have a need to turn optimizations off.
*)
{$IFOPT O+} //OPTIMIZATION
	Add('Optimization: ON');
{$ELSE}
	Add('Optimization: OFF');
{$ENDIF}

(*
	Enabling overflow checking slows down your program and makes it somewhat larger, so use {$Q+} only for debugging.
*)
{$IFOPT Q+} //OVERFLOWCHECKS
	Add('Overflow Checking: ON');
{$ELSE}
	Add('Overflow Checking: OFF');
{$ENDIF}

(*
	Enabling range checking slows down your program and makes it somewhat larger.
*)
{$IFOPT R+} //RANGECHECKS
	Add('Range Checking: ON');
{$ELSE}
	Add('Range Checking: OFF');
{$ENDIF}

{$IFOPT W+} //STACKFRAMES
	Add('Stack frames: ON');
{$ELSE}
	Add('Stack frames: OFF');
{$ENDIF}

{$IFOPT I+} //IOCHECKS
	Add('I/O Checking: ON');
{$ELSE}
	Add('I/O Checking: OFF');
{$ENDIF}
end;

//procedure TBCryptTests.SelfTest;
//begin
//	CheckTrue(TBCrypt.SelfTest);
//end;

procedure TBCryptTests.SelfTestA_KnownTestVectors;
begin
	if not FindCmdLineSwitch('SlowUnitTests', ['/', '-'], True) then
	begin
		Status('Very slow test. Specify -SlowUnitTests to include');
		Exit;
	end;

  Assert.IsTrue(SelfTestA);
end;

procedure TBCryptTests.SelfTestB_Base64EncoderDecoder;
begin
  Assert.IsTrue(SelfTestB);
end;

procedure TBCryptTests.SelfTestC_UnicodeStrings;
begin
	if not FindCmdLineSwitch('SlowUnitTests', ['/', '-'], True) then
	begin
		Status('Very slow test. Specify -SlowUnitTests to include');
		Exit;
	end;

  Assert.IsTrue(SelfTestC);
end;

procedure TBCryptTests.SelfTestD_VariableLengthPasswords;
begin
	if not FindCmdLineSwitch('SlowUnitTests', ['/', '-'], True) then
	begin
		Status('Very slow test. Specify -SlowUnitTests to include');
		Exit;
	end;

  Assert.IsTrue(SelfTestD);
end;

procedure TBCryptTests.SelfTestE_SaltRNG;
begin
  Assert.IsTrue(SelfTestE);
end;

procedure TBCryptTests.SelfTestF_CorrectBattery;
var
    elapsedTimeStopWatch : TStopwatch;
    elapsed : TTimeSpan;
begin
    elapsedTimeStopWatch := TStopwatch.StartNew;
    Assert.IsTrue(SelfTestF);
    elapsed := elapsedTimeStopWatch.Elapsed;

    Status(Format('%.4f ms', [elapsed.TotalMilliseconds]));

    Status(GetCompilerOptions);
end;

procedure TBCryptTests.SelfTestG_PasswordLength;
begin
  Assert.IsTrue(SelfTestG);
end;

procedure TBCryptTests.SelfTestH_OpenBSDLengthBug;
begin
  Assert.IsTrue(SelfTestH);
end;

procedure TBCryptTests.SelfTestI_UnicodeCompatibleComposition;
begin
  Assert.IsTrue(SelfTestI);
end;

procedure TBCryptTests.SelfTestJ_NormalizedPasswordsMatch;
begin
  Assert.IsTrue(SelfTestJ);
end;

procedure TBCryptTests.SelfTestK_SASLprep;
begin
  Assert.IsTrue(SelfTestK);
end;

procedure TBCryptTests.SelfTestL_Prehash;
begin
  Assert.IsTrue(SelfTestL);
end;

procedure TBCryptTests.SpeedTests;

	procedure TimeIt(Cost: Integer);
	var
		timems: Real;
		bestTime: Real;
		n: Integer;
    elapsedTimeStopWatch : TStopwatch;
    elapsed : TTimeSpan;
	begin
		bestTime := 0;

		n := 5;
    while n > 0 do
    begin
        elapsedTimeStopWatch := TStopwatch.StartNew;
        TBCrypt.HashPassword('corrent horse battery staple', Cost);
        elapsed := elapsedTimeStopWatch.Elapsed;

        Dec(n);

        timems := elapsed.TotalMilliseconds; //milliseconds
        if (bestTime = 0) or (timems < bestTime) then
        begin
            bestTime := timems;
            n := 5; //we found a new min. Wait until we get five min in a row
        end;
    end;

		Status(Format('BCrypt, cost=%d: %.2f ms', [cost, bestTime]));
	end;
begin
	TimeIt(8);
	TimeIt(9);
	TimeIt(10);
	TimeIt(11);
	TimeIt(12);
	TimeIt(13);
	TimeIt(14);
	TimeIt(15);
//DebugOutput('SAMPLING ON');
	TimeIt(16);
//DebugOutput('SAMPLING OFF');
//	TimeIt(17);
end;

procedure TBCryptTests.TestEnhancedHash;
var
	expectedHash: string;
	passwordRehashNeeded: Boolean;
	passwordValid: Boolean;
begin
	expectedHash := TBCrypt.EnhancedHashPassword('correct battery horse staple');
  Assert.IsTrue(expectedHash <> '');

	passwordValid := TBcrypt.CheckPassword('correct battery horse staple', expectedHash, {out}passwordRehashNeeded);
  Assert.IsTrue(passwordValid);
end;

procedure TBCryptTests.TestParseEnhancedHash;
var
	bRes: Boolean;
	hash: string;
	version: string;
	cost: Integer;
	actualSalt: TBytes;
	actualSaltBase64: string;
	isEnhanced: Boolean;
begin
	hash := '$bcrypt-sha256$2a,12$LrmaIX5x4TRtAwEfwJZa1.$2ehnw6LvuIUTM0iz4iz9hTxv21B6KFO';

	bRes := TBCrypt.TryParseHashString(hash, {out}version, {out}cost, {out}actualSalt, {out}isEnhanced);
  Assert.IsTrue(bRes);

  Assert.AreEqual('2a', version);
	Assert.AreEqual(12, cost);
	Assert.AreEqual(True, isEnhanced); //is enhanced

	actualSaltBase64 := TBCrypt.BsdBase64Encode(actualSalt, Length(actualSalt));
	Assert.AreEqual('LrmaIX5x4TRtAwEfwJZa1.', actualSaltBase64);
end;

procedure TBCryptTests.Test_ManualSystem;
var
	salt: TBytes;
	hash: TBytes;
	password: string;
	validPassword: Boolean;
	passwordRehashNeeded: Boolean;
begin
	{
		Normally bcrypt hashes to an OpenBSD password-file compatible string (i.e. $2b$...)
		But if you want to handle the salt, and hash bytes directly, and come up with your own serialization format
		you can do that too
	}
	password := 'correct horse battery staple';
	salt := TBCrypt.GenerateSalt;

	hash := TBCrypt.HashPassword(password, salt, 4); //4 is the lowest cost we'll accept

	validPassword := TBCrypt.CheckPassword(password, salt, hash, 4, {out}passwordRehashNeeded);
  Assert.IsTrue(validPassword);
  Assert.IsTrue(passwordRehashNeeded, 'Expected passwordRehashNeede to be true, given that we used a cost of 4');
end;

procedure TBCryptTests.Test_ParseHashString;

	procedure t(HashString: string; ExpectedResult: Boolean; ExpectedVersion: string; ExpectedCost: Integer;
			ExpectedSaltBase64: string; TestSituation: string);
	var
		actualVersion: string;
		actualCost: Integer;
		actualSalt: TBytes;
		actualIsEnhanced: Boolean;
		actualSaltBase64: string;
		actualResult: Boolean;
	begin
//		expectedSalt := TBCrypt.BsdBase64Decode(ExpectedSaltBase64);
		actualResult := TBCrypt.TryParseHashString(HashString, {out}actualVersion, {out}actualCost, {out}actualSalt, {out}actualIsEnhanced);

		Assert.AreEqual(expectedResult, actualResult, HashString+'   '+TestSituation);
		if actualResult then
		begin
			Assert.AreEqual(ExpectedVersion, actualVersion, 'Version for hash: '+HashString+'   '+TestSituation);
			Assert.AreEqual(ExpectedCost, actualCost, 'Cost for hash: '+HashString+'   '+TestSituation);

			actualSaltBase64 := TBCrypt.BsdBase64Encode(actualSalt, Length(actualSalt));
			Assert.AreEqual(expectedSaltBase64, actualSaltBase64, 'Salt for hash: '+HashString+'   '+TestSituation);

			//These are non-enhanced hash strings (expect False)
			Assert.AreEqual(False, actualIsEnhanced, 'Is Enhanced for hash: '+HashString+'	'+TestSituation);
		end;
	end;
begin
	t('$2c$06$DCq7YPn5Rq63x1Lad4cll.', True, '2c', 6, 'DCq7YPn5Rq63x1Lad4cll.', 'Future version suffix - 2c');
	t('$2b$06$DCq7YPn5Rq63x1Lad4cll.', True, '2b', 6, 'DCq7YPn5Rq63x1Lad4cll.', 'Current version suffix - 2b');
	t('$2a$06$DCq7YPn5Rq63x1Lad4cll.', True, '2a', 6, 'DCq7YPn5Rq63x1Lad4cll.', 'Most common version suffix - 2a');
	t('$2y$06$DCq7YPn5Rq63x1Lad4cll.', True, '2y', 6, 'DCq7YPn5Rq63x1Lad4cll.', 'Crypt_blowfish fixed hash version - 2y');
	t('$2x$06$DCq7YPn5Rq63x1Lad4cll.', True, '2x', 6, 'DCq7YPn5Rq63x1Lad4cll.', 'Crypt_blowfish buggy hash version - 2x');
	t('$2$06$DCq7YPn5Rq63x1Lad4cll.',  True, '2',  6, 'DCq7YPn5Rq63x1Lad4cll.', 'Original bcrypt version - 2');

	t('$2c$6$DCq7YPn5Rq63x1Lad4cll.', True, '2c', 6, 'DCq7YPn5Rq63x1Lad4cll.', 'Single digit cost factor "6"');
	t('$2b$06$DCq7YPn5Rq63x1Lad4cll.', True, '2b', 6, 'DCq7YPn5Rq63x1Lad4cll.', 'Two digit cost factor "06"');
	t('$2a$006$DCq7YPn5Rq63x1Lad4cll.', True, '2a', 6, 'DCq7YPn5Rq63x1Lad4cll.', 'Triple digit cost factor "006"');

	t('$2c$0$DCq7YPn5Rq63x1Lad4cll.', False, '2c', 0, 'DCq7YPn5Rq63x1Lad4cll.', 'Zero cost factor is not valid');
	t('$2c$$DCq7YPn5Rq63x1Lad4cll.', False, '2c', 0, 'DCq7YPn5Rq63x1Lad4cll.', 'Empty cost factor is not valid');

	t('$3$6$DCq7YPn5Rq63x1Lad4cll.', False, '3', 6, 'DCq7YPn5Rq63x1Lad4cll.', 'Unknown version number');
	t('$20$6$DCq7YPn5Rq63x1Lad4cll.', False, '20', 6, 'DCq7YPn5Rq63x1Lad4cll.', 'Version suffix can only be a letter');
	t('$2_$6$DCq7YPn5Rq63x1Lad4cll.', False, '2_', 6, 'DCq7YPn5Rq63x1Lad4cll.', 'Version suffix can only be a letter');
	t('$2ca$6$DCq7YPn5Rq63x1Lad4cll.', False, '2ca', 6, 'DCq7YPn5Rq63x1Lad4cll.', 'Version string can be at most 2 characters ("2" + "letter")');

	t('$2C$6$DCq7YPn5Rq63x1Lad4cll.', True, '2C', 6, 'DCq7YPn5Rq63x1Lad4cll.', 'Version suffix may also be UPPERCASE');

	t('$2a', False, '2a', 0, '', 'Missing everything after version');
	t('$2a$', False, '2a', 0, '', 'Missing everything after version');
	t('$2a$6', False, '2a', 6, '', 'Missing everything after cost factor');
	t('$2a$6$', False, '2a', 6, '', 'Missing everything after cost factor');
	t('$2a$6$DCq7YPn5Rq63x1Lad4cll', False, '2a', 6, 'DCq7YPn5Rq63x1Lad4cll', 'Salt is too short');
end;

initialization
	TDUnitX.RegisterTestFixture(TBCryptTests);

end.
