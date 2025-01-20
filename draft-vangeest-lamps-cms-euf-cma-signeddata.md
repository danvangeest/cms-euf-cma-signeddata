---
title: "EUF-CMA for the Cryptographic Message Syntax (CMS) SignedData"
abbrev: "EUF-CMA for CMS SignedData"
category: std

docname: draft-vangeest-lamps-cms-euf-cma-signeddata-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Limited Additional Mechanisms for PKIX and SMIME"
keyword:
 - Cryptographic Message Syntax
 - CMS
venue:
  group: "Limited Additional Mechanisms for PKIX and SMIME"
  type: "Working Group"
  mail: "spasm@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/spasm/"
  github: "danvangeest/cms-euf-cma-signeddata"
  latest: "https://danvangeest.github.io/cms-euf-cma-signeddata/draft-vangeest-lamps-cms-euf-cma-signeddata.html"

author:
  -
    fullname: Daniel Van Geest
    ins: D. Van Geest
    organization: CryptoNext Security
    email: daniel.vangeest@cryptonext-security.com
  -
    fullname: Falko Strenzke
    organization: MTG AG
    email: falko.strenzke@mtg.de

normative:

informative:
  FIPS204: DOI.10.6028/NIST.FIPS.204
  FIPS205: DOI.10.6028/NIST.FIPS.205
  LAMPS121:
    target: https://datatracker.ietf.org/meeting/121/materials/slides-121-lamps-cms-euf-cma-00
    title: "EUF-CMA for CMS SignedData"
    author:
      -
        ins: F. Strenzke
    date: 2024-11-06
  Str23:
    target: https://ia.cr/2023/1801
    title: "ForgedAttributes: An Existential Forgery Vulnerability of CMS and PKCS#7 Signatures"
    author:
      -
        ins: F. Strenzke
    date: 2023-11-22
    format:
      PDF: https://eprint.iacr.org/2023/1801.pdf


--- abstract

The Cryptographic Message Syntax (CMS) has different signature verification behaviour based on whether signed attributes are present or not.
This results in a potential existential forgery vulnerability in CMS and protocols which use CMS.
This document describes the vulnerability and lists a number of potential mitigations for LAMPS working group discussion.


--- middle

# Introduction

The Cryptographic Message Syntax (CMS) {{!RFC5652}} signed-data content type allows any number of signers in parallel to sign any type of content.

CMS gives a signer two options when generating a signature on some content:

- Generate a signature on the whole content; or
- Compute a hash over the content, place this hash in the message-digest attribute in the SignedAttributes type, and generate a signature on the SignedAttributes.

The resulting signature does not commit to the presence of the SignedAttributes type, allowing an attacker to influence verification behaviour.
An attacker can perform two different types of attacks:

1. Take an arbitrary CMS signed message M which was originally signed with SignedAttributes present and remove the SignedAttributes, thereby crafting a new message M' that was never signed by the signer.  M' has the DER-encoded SignedAttributes of the original message as its content and verifies correctly against the original signature of M.
2. Let the signer sign a message of the attacker's choice without SignedAttributes.
   The attacker chooses this message to be a valid DER-encoding of a SignedAttributes object.
   He can then add this encoded SignedAttributes object to the signed message and change the signed message to the one that was used to create the messageDigest attribute within the SignedAttributes.
   The signature created by the signer is valid for this arbitrary attacker-chosen message.

This vulnerability was presented by Falko Strenzke at IETF 121 [LAMPS121] and is detailed in [Str23].

Due to the limited flexibility of either the signed or the forged message in either attack variant, the fraction of vulnerable systems can be assumed to be small. But due to the wide deployment of the affected protocols, such instances cannot be excluded.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Potential Mitigations

Potential mitigations are described in the following sub-sections as input to the working group discussion.
If this draft is adopted and the working group has taken a decision which measure(s) should be realized, we'll describe the chosen measures in detail.

The mitigations in this section make use of a context string which is passed to the signature algorithm's sign and verify functions.

ML-DSA [FIPS204], SLH-DSA [FIPS205], Composite ML-DSA {{?I-D.ietf-lamps-pq-composite-sigs}}, and Ed448 {{?RFC8032}} take a context string during signing and verification.
The context string may be up to 255 bytes long.
By default the context string is the empty string.

~~~
   Sign(sk, M, ctx="")
   Verify(sk, M, ctx="")
~~~

RSA, ECDSA and Ed25519 signatures do not take a context string and would not be helped by these mitigations.

Ed448 can take a context string but does not currently in CMS {{?RFC8419}}.

Ed25519ctx {{?RFC8032}} takes a context string but is not specified for use in CMS.

## Immediate Forced Use of Specific Signature Context Strings {#immediate}

Immediately update {{?I-D.ietf-lamps-cms-ml-dsa}}, {{?I-D.ietf-lamps-cms-sphincs-plus}}, and {{?I-D.ietf-lamps-pq-composite-sigs}} to require a context string, with a different value for use with and without signated attributes.

When signed attributes are present:

~~~
   Sign(sk, M, "signed-attributes")
   Verify(sk, M, "signed-attributes")
~~~

When signed attributes are absent:

~~~
   Sign(sk, M, "no-signed-attributes")
   Verify(sk, M, "no-signed-attributes")
~~~

Unlike the following mitigations, Ed448 cannot be addressed by this mitigation because it is already published and in use.

## Attribute-Specified Use of Implicit Signature Context Strings {#implicit}

Like {{immediate}}, but the use of the signature context string is indicated by a new, empty (or attribute value ignored), sign-with-context-implicit unsigned attribute.

{{I-D.ietf-lamps-cms-ml-dsa}}, {{I-D.ietf-lamps-cms-sphincs-plus}}, and {{I-D.ietf-lamps-pq-composite-sigs}} can be published using the default signature context string.  ML-DSA, SLH-DSA, Composite-ML-DSA, and Ed448 only use the non-default context string when the new attribute is used.

### Signing

When signed attributes are present:

~~~
   unsigned-attributes.add(sign-with-context-implicit)
   Sign(sk, M, "signed-attributes")
~~~

When signed attributes are absent:

~~~
   unsigned-attributes.add(sign-with-context-implicit)
   Sign(sk, M, "no-signed-attributes")
~~~

### Verifying

When signed attributes are present:

~~~
   IF unsigned-attributes.contains(sign-with-context-implicit)
   THEN Verify(sk, M, "signed-attributes")
   ELSE Verify(sk, M, "")
~~~

When signed attributes are absent:

~~~
   IF unsigned-attributes.contains(sign-with-context-implicit)
   THEN Verify(sk, M, "no-signed-attributes")
   ELSE Verify(sk, M, "")
~~~

## Attribute-Specified Use of Explicit Signature Context Strings

Like {{implicit}} but the new unsigned attribute (sign-with-context-explict) contains a semi-colon-delimited list of keyword (and optional value) strings.
This addresses the possibility of future CMS features that require context parameters.

~~~
   ctx = "<keyword_1>[=value1];...;<keyword_n>[=value]"
~~~

The list is ordered alphabetically by type string.
This list is validated by the verifier and used as the signature context string.
(alternative: the SHA-256 hash of the list is used as the signature context string to avoid it getting too long)

A proposed list of initial signature context string keywords follows:

| keyword | value | comment |
|-|-|-|
| "IETF/CMS" | | REQUIRED to be in the sign-with-context-implicit attribute, to differentiate a signature in CMS from a signature with the same private key over some other data. |
| "signed-attrs" | | Present if signed attributes are used, not present if signed attributes are not used. Alternative: always present, value = 0/1, yes/no depending on whether signed attributes are present or not. |
| "app-ctx" | base64( SHA-256( protocol_context ) ) | Allows the protocol using CMS to specify a context. SHA-256 is applied so that the length available to the protocol context isn't dependent on the other context values used in CMS. (alternative: no SHA-256 here, apply SHA-256 to the whole CMS context). base64-encoding is applied so the app context doesn't introduce semi-colons to mess up CMS' parsing of this string. |
{: title="Potential Context String Keywords"}

When a verifier processes a SignerInfo containing the sign-with-context-explicit attribute, it MUST perform the following consistency checks:

- If the "signed-attrs" keyword is present and SignedAttributes is not present in the SignerInfo, fail verification.
- If the "signed-attrs" keyword is not present and SignedAttributes is present in the SignerInfo, fail verification.

If the consistency checks pass, the signature is verified using the string in the sign-with-context-explicit attribute as the signature context (alternative: using SHA-256 of the string in the sign-with-context-explicit attribute).

When a verifier processes a SignerInfo without the sign-with-context-explicit attribute, they MUST verify the signature using the default signature context value ("").

{{I-D.ietf-lamps-cms-ml-dsa}}, {{I-D.ietf-lamps-cms-sphincs-plus}}, and {{I-D.ietf-lamps-pq-composite-sigs}} can be published using the default signature context string.  ML-DSA, SLH-DSA, Composite-ML-DSA, and Ed448 only use the non-default context string when the new attribute is used.

# Straw Mitigations

The following mitigations might not be good ideas but are included just in case there's a seed of genius in them.

## Attack Detection in CMS {#attack-detection}

If SignedAttributes is not present, check if the signed message is a valid DER-encoded SignedAttributes structure and fail if it is.
The mandatory contentType and messageDigest attributes, with their respective OIDs, should give a low probability of a legitimate message being flagged.

If an application protocol deliberately uses such a signed messages, verification would fail.

This mitigation does not address the inverse problem where a protocol doesn't used SignedAttributes but for some reason often sends messages which happen to be formatted like valid SignedAttributes encodings, with attacker-controlled bytes where the message digest attribute would be.

## Always/Never use SignedAttributes in Your Protocol

Individually update each protocol which use CMS to always require or forbid signed attributes.

## Attack Detection in Your Protocol

{{attack-detection}} but specified in the protocol that uses CMS rather than CMS itself.

# RFCs Using the id-data eContentType

The RFCs in the following subsections use the id-data eContentType. This table summarizes their usages of signed attributes.

| RFC | Signed Attributes Usage |
|-|-|
| {{?RFC8994}} | Appears to require the used of signed attributes |
| {{?RFC8572}} | Says nothing about signed attributes |
| {{?RFC8551}} | RECOMMENDS signed attributes |
| {{?RFC6257}} | Forbids signed attributes |
| {{?RFC5751}} | RECOMMENDS signed attributes |
| {{?RFC5655}} | Says nothing about signed attributes |
| {{?RFC5636}} | Forbids signed attributes |
| {{?RFC5126}} | Requires signed attributes |
| {{?RFC5024}} | Says nothing about signed attributes |
| {{?RFC3851}} | RECOMMENDS signed attributes |
| {{?RFC3126}} | Requires signed attributes |
| {{?RFC2633}} | RECOMMENDS signed attributes |
{: title="RFCs using id-data"}

An RFC requiring or forbidding signed attributes does not mean that a verifier will enforce this requirement when verifying, their CMS implementation may simply process the message whether or not signed attributes are present.

## RFC 8894 Simple Certificate Enrolment Protocol

Figure 6 in {{Section 3 of ?RFC8894}} specifies id-data as the eContentType, and shows the use of signedAttrs.  The document itself never refers to signed attributes, but instead to authenticated attributes and an authenticatedAttributes type.  Errata ID 8247 has been filed to clarify this.

Since SCEP seems to require the use of signedAttrs with the id-data eContentType, it is not affected by this attack.

## RFC 8572 Secure Zero Touch Provisioning (SZTP)

{{Section 3.1 of ?RFC8572}} allows the use of the id-data eContentType, although it also defines more specific content types.  It does not say anything about signed attributes.

## S/MIME RFCs

{{?RFC8551}}, {{?RFC5751}}, {{?RFC3851}}, and {{?RFC2633}} require the use of the id-data eContentType.

{{Section 2.5 of ?RFC8551}} says:

> Receiving agents MUST be able to handle zero or one instance of each
of the signed attributes listed here.  Sending agents SHOULD generate
one instance of each of the following signed attributes in each
S/MIME message:

and

> Sending agents SHOULD generate one instance of the signingCertificate
or signingCertificateV2 signed attribute in each SignerInfo
structure.

So the use of signed attributes is not an absolute requirement.

## RFC 6257 Bundle Security Protocol Specification

{{Section 4 of ?RFC6257}} says:

> In all cases where we use CMS, implementations SHOULD NOT include
additional attributes whether signed or unsigned, authenticated or
unauthenticated.

## RFC 5655 IP Flow Information Export (IPFIX)

{{?RFC5655}} is a file format that uses CMS for detached signatures. It says nothing about the use of signed attributes.

## RFC 5636 Traceable Anonymous Certificate

{{Section C.1.2 of ?RFC5636}} says:

> The signedAttr element MUST be omitted.

## RFC 5126 CMS Advanced Electronic Signatures (CAdES)

{{Section 4.3.1 of ?RFC5126}} specifies mandatory signed attributes.

## RFC 5024 ODETTE File Transfer Protocol 2

{{?RFC5024}} uses the id-data eContentType and says nothing about signed attributes.

## RFC 3126 Electronic Signature Formats for long term electronic signatures

{{Section 6.1 of ?RFC3126}} requires the MessageDigest attribute, which is a signed attribute.


# Security Considerations

TODO Security

The vulnerability is not present in systems where the use of SignedAttributes is mandatory, for example: SCEP, Certificate Transparency, RFC 4018 firmware update, German Smart Metering CMS data format.
However, this security relies on a correct implementation of the verification routine that ensures the presence of SignedAttributes.

The vulnerability is also not present when the message is signed and then encrypted, as the attacker cannot learn the signature.

Conceivably vulnerable systems (TODO: describe these better):

- Unencrypted firmware update denial of service
- Dense message space
- Signing unstructured data
- External signatures over unstructured data
- Systems with permissive parsers


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
