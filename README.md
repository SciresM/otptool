# NAME

**otptool** - view and extract data from a 3DS OTP

# SYNOPSIS

**otptool**
\[**-c** *ctcert\_out*]
\[**-d** *decrypted\_otp\_out*]
\[**-Dh**]
*otp*

# DESCRIPTION

The
**otptool**
utility views and extracts data from a 3DS OTP dump.
The dump can be either encrypted or already decrypted.
If no arguments are given, no files will be written.

The options are as follows:

**-c** *ctcert\_out*

> Generate the CTCert from the OTP and write the CTCert to
> *ctcert\_out*.

**-d** *decrypted\_otp\_out*

> Write the decrypted OTP to
> *decrypted\_otp\_out*.
> Some utilities require a decrypted OTP,
> such as yellows8's boot9\_aeskeytool\_conunique.sh from boot9\_tools.

**-D**

> Use the development key and IV rather than the retail ones for
> decryption.
> This option is used to handle OTPs from development units.

The displayed fields mean:

Device ID

> Every 3DS unit has a unique device identifier (ID).
> This is used, amongst other things, for the eShop infrastructure.

Fallback keyY

> This data is used as fallback keyY data if
> *nand:/private/movable.sed*
> does not exist or is invalid.
> Internally, this is actually a series of two additional 64-bit
> console-unique IDs,
> but they are never used as such in practice.

Version

> This specifies the OTP version.
> It seems that earlier versions of Nintendo's operating systems also had
> OTPs of some sort, hence the version field.

Is dev unit

> If
> "true",
> this is a dev unit.
> If
> "false",
> this is not a dev unit.
> Note that this is separate from the decryption process &#8211; it's
> theoretically possible that an OTP uses dev encryption but then
> specifies a retail console, but has never been specified in the wild.

Manufactured

> Date and time when this unit was manufactured/the OTP was written.
> The actual NAND flashing process and unit assembly may take place at a
> later time.

CTCert expiry

> The CTCert can expire.
> The expiry time seems to be exactly 20 years after the manufacturing
> date as described above.

EC PrivKey

> Private key for the sect233r1 elliptic curve.
> Seems to be specified as R followed by S in big-endian.

Signature

> An ECDSA signature over the CTCert using curve sect233r1.

# BUILDING

To build
**otptool**,
just type
**make**.
You require a POSIX-compatible environment for getopt(3).
Additionally, you require libgcrypt at version 1.4.0 or above;
**otptool**
may work on lower versions, but this hasn't been tested.
For Windows, openssl is also needed.

# BUGS

The CTCert signature is not verified.
As the OTP already has a hash that can be used to verify,
it does not seem to be worthwhile.

