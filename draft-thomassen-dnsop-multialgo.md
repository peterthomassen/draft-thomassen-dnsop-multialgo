%%%
Title = "DNSSEC Multi-Algorithm Requirements"
abbrev = "multialgo"
docname = "@DOCNAME@"
category = "std"
ipr = "trust200902"
updates = [4035, 6840, 8624]
area = "Internet"
workgroup = "DNSOP Working Group"
date = @TODAY@

[seriesInfo]
name = "Internet-Draft"
value = "@DOCNAME@"
stream = "IETF"
status = "standard"

[[author]]
initials = "P."
surname = "Thomassen"
fullname = "Peter Thomassen"
organization = "deSEC, SSE"
[author.address]
 email = "peter@desec.io"
[author.address.postal]
 city = "Berlin"
 country = "Germany"

[[author]]
initials = "V."
surname = "Dukhovni"
fullname = "Viktor Dukhovni"
organization = "Google LLC"
[author.address]
 email = "ietf-dane@dukhovni.org"
%%%


.# Abstract

This document restates the requirements on DNSSEC signing and validation and
makes small adjustments in order to allow for more flexible handling of
configurations that advertise multiple Secure Entry Points (SEP) with different
signing algorithms via their DS record or trust anchor set.
The adjusted rules allow both for multi-signer operation and for transfer of
signed DNS zones between providers, without requiring that each provider uses
the same signing algorithm.
In addition, the proposal enables pre-publication of a trust anchor in
preparation for an algorithm rollover, such as of the root zone.

This document updates RFCs 4035, 6840, and 8624. 

{mainmatter}


# Introduction

DNSSEC [@!RFC4033;@!RFC4034;@!RFC4035;@!RFC6840;@!RFC9364] adds origin
authentication to the DNS protocol. While it typically works smoothly when using
a single signing algorithm, complications can occur when multiple algorithms are
in use.

In particular, current specifications [@!RFC4035;@!RFC6840] require that a zone
be signed with each signing algorithm listed in a zone's DS RRset or appearing
via its trust anchors. This poses a problem for (at least) the following cases:

  * In multi-signer setups where each DNS provider maintains their own key
    ([@!RFC8901] Section 2.1.2), providers may not necessarily choose the same
    signing algorithm. (For example, one may choose to use algorithm 8 while the
    other picks algorithm 13, both of which will appear in the domain's DS
    RRset.) While such setups do allow establishing a chain of trust, DNS
    responses from either provider will only contain signatures of the one
    signing algorithm used by that provider, violating the specification.

  * A related issue is the transfer of a signed domain name from one provider to
    another, which requires a short multi-signer period in order to execute a
    glitch-free transition without disabing DNSSEC for the domain.
    If the old and the new provider do not use the same signing algorithms,
    the same problems appear.

  * When performing an algorithm rollover for a zone with a trust anchor,
    current specifications mandate that the zone has to be double-signed with
    both the old and the new algorithm before publishing the new trust anchor.
    For the root zone, this could lead to a potentially rather long phase of
    double-signing (on the order of a year). As this comes with both financial
    and SSR costs, it seems desirable to find a way for publishing the new trust
    anchor without introducing the new algorithm into the zone just yet.

<!-- Viktor: What is an "SSR cost"? -->

For a more detailed explanation of the implications of the current rules as well
as of alternative solution approaches, see (#oldrules).

The existing signing requirements, that give rise to the above limitations, are
well motivated.  They ensure the downgrade-resistance of DNSSEC when only some,
but not all, of a zone's DS RRset or trust anchor set DNSKEY algorithms are
supported by a validating resolver.

When a zone's DS RRset or trust anchor set includes multiple DNSKEY algorithms,
an attacker who can strip all the supported RRSIGs from a signed response from
that zone, leaving just the unsupported signatures, must not be able to
disable validation for that zone, effectively downgrading the zone to
"insecure".

This document explores how the signing and validation rules can be modified to
accommodate additional use cases, without compromising on the security
guarantees given by DNSSEC.

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**",
"**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**",
"**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and
"**OPTIONAL**" in this document are to be interpreted as described in
BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all
capitals, as shown here.

# Proposed Updates to RFCs

The heart of the issue is that even though any one acceptable signature 
suffices for validation, the signer cannot, in the general case, know which
particular signing algorithm(s) the validator will support -- and hence,
providing a "large enough set" (read: all of them) is the approach that had
been taken so far.

This document presents a more relaxed approach which does not require all algorithms'
RRSIGs to be present, while ensuring that the set of signatures provided is
still "large enough" for reliable DNSSEC operation, so that glitch-free
multi-signer operation and TA pre-publication are made possible.
This is enabled by a new mechanism that allows the signer to determine which
RRSIGs can be skipped, without risking validation failures.

For the case of a multi-signer setup with two generally supported
algorithms (such as 8 and 13), the scheme requires only one of the
two signatures.  Similarly, when pre-publishing a trust anchor,
associated signatures don't need to be published immediately,
provided that the existing TA's algorithm is generally supported.

## Updates to RFC 8624

The notion of UNIVERSAL signing algorithms is introduced, and defined
as follows:

 *  The information contained in the table of [@!RFC8624] Section 3.1 is
    transferred into a to-be-erected IANA registry, and a boolean
    column is added with the heading "universal validation support".
    Signing algorithms where this column is TRUE are called
    "UNIVERSAL".

 *  "MUST NOT sign" algorithms can never be UNIVERSAL.  "MUST
    validate" is a prerequisite for UNIVERSAL.  Changes that affect
    whether an algorithm is UNIVERSAL require standards action.

 *  Algorithms 8 and 13 are the only algorithms currently declared
    UNIVERSAL.

Also, new terminology is established for algorithms in "MUST NOT
sign" status: those are called "INSECURE".

As soon as a "MUST validate" algorithm is known or expected to have declining
validation support, it should be moved to status "MUST NOT sign" (which
removes the UNIVERSAL label if present, and renders the algorithm INSECURE).
Accordingly, algorithms 5 and 7 are declared "MUST NOT sign".

The following algorithms are thus INSECURE: 1, 3, 5, 6, 7, 12

## Signing Requirements

 1. Signers must sign with at least one UNIVERSAL algorithm if at
    least one UNIVERSAL algorithm is present in the DS RRset or trust
    anchor set.  Other signatures are OPTIONAL.

 2. Absent any UNIVERSAL algorithms in the DS RRset or trust anchor
    set, signers MUST sign with all algorithm listed.

## Validator Requirements

 1. When the DS RRset or trust anchor set for a zone includes an
    unsupported INSECURE algorithm, validators MUST be willing to treat the
    zone as unsigned, even if the DS RRset or trust anchor set lists another
    supported algorithm.  More specifically, unvalidated responses bearing
    just the unsupported RRSIGs MUST be accepted as valid "insecure" responses.
    Response RRsets with supported signatures SHOULD still be validated.

 2. Otherwise, validators MUST accept any valid path.

Implementing these rules requires validating resolvers to keep a record of
INSECURE algorithms (e.g. via a static array of INSECURE algorithm numbers), so
that the zone's security status can be established upon inspection of a DS
record or TA set.  Any otherwise supported algorithms that are disabled by the
resolver operator as a matter of local policy MUST also be considered
"INSECURE".

## Discussion

It is observed that both signers and validators need to know only one of the
concepts "UNIVERSAL" and "INSECURE": to use several signing algorithms, signers
only need to know which algorithms are UNIVERSAL, while validators only need to
know which are INSECURE. This limits the implementation effort.

The new validation requirements enable stable multi-signer setups using
UNIVERSAL algorithms as well as glitch-free provider transfers and algorithm
upgrades from INSECURE to UNIVERSAL algorithms (such as algorithm 7 to 13),
without risking SERVFAIL responses in the event that a resolver no longer
supports one of the algorithms (e.g. 7). For a detailed discussion, see
(#security).

DNS providers in a multi-signer setup are free to limit their responses to serve
signatures for one UNIVERSAL algorithm only. This one signature is sufficient to
provide a valid path everywhere.

When a UNIVERSAL algorithm is in use, signatures of other algorithms are not
required. DNS providers are thus free to introduce additional (non-INSECURE)
algorithms without forcing other participating providers to do the same.

For zones with trust anchors, when there is a trust anchor with a UNIVERSAL
algorithm, it is permissible to introduce a new trust anchor for a different
algorithm before introducing the corresponding DNSKEY and RRSIGs into the zone.
(Of course, they need to be added before the old trust anchor is removed.)

If the added trust anchor is also for a UNIVERSAL algorithm, it is permissible
to eventually switch to returning just the RRSIGs for the new algorithm, without
an intermediate dual-signing period.  If the new trust anchor is not yet UNIVERSAL,
a dual signing period is required in order to complete the algorithm rollover.

In most cases, particularly in the case of the root zone, both algorithms will
be UNIVERSAL.  In a hypothetical emergency situation where only the new
algorithm is UNIVERSAL and the old was just downgraded to INSECURE, the new
signatures would need to be introduced immediately.  A short dual signing
period would then be required for continuity.  Resolvers would be expected to
defer disabling the old algorithm until after the root zone rollover is
completed.

# IANA Considerations

[This section needs to be updated to describe the construction of the new IANA
registry for the implementation status and requirements of DNSSEC signing
algorithms.]


{#security}
# Security Considerations

## Algorithm Transitions

The new validation requirements guarantee that when a zone is in a multi-signer
setup with two algorithms, the security level is the same as it would be if the
zone was in a single-signer setup using the weakest of them (from the resolver's
perspective). This resolves undue SERVFAIL issues that could occur with certain
algorithm combinations under the previous rules.

For example, a zone using only algorithm 7 is treated as insecure by resolvers
that do not support this algorithm. When transferring the domain to another
provider via a multi-signer setup with algorithm 13, the zone's security status
remains "insecure", as the DS RRset still includes INSECURE algorithm 7. The
presence of algorithm 13 is inconsequential at this point. Only once algorithm 7
is removed, the zone turns secure.

This rule prevents validation breakage when the resolver encounters an
unsupported RRSIG from an outdated algorithm, and instead acknowledges the fact
that the signer is using an algorithm that is in "MUST NOT sign" status, which
(depending on resolver support) might render the zone insecure. This allows for
glitch-free algorithm upgrades, with the security status of the zone changing
only once the transition is complete.

Resolvers supporting both algorithms retain full validation
throughtout the transition.  In case of a permanent multi-signer
setup, the zone maintainer needs to upgrade the INSECURE algorithm to
a UNIVERSAL one in order to restore universal validation.

## Time Dependency of UNIVERSAL Algorithms

The same situation occurs when an algorithm is removed from the set
of UNIVERSAL algorithms.  In this case, the algorithm will enter
"MUST NOT sign" status and become INSECURE.  If the zone continues to
use the INSECURE algorithm, it will continue to fully validate with
supporting resolvers, while non-supporting resolvers will treat the
zone as insecure until the algorithm is replaced.

Conversely, when an algorithm is added to the set of UNIVERSAL ones, signers
MAY begin to return signatures for just that algorithm.  This is, in fact, not
a problem, as resolvers do not need to know the concept of UNIVERSAL, they just
need to support that algorithm (or in less typically explicitly classify it as
INSECURE).  A problem could only occur if the corresponding RRSIG was not
supported by a non-negligible population of resolvers; however, in that case
labeling the algorithm as UNIVERSAL would have been premature.  Determining
universal support cannot be solved on the protocol level, and it is the
community's responsibility to only advance an algorithm to UNIVERSAL when safe
enough, i.e. when the population of resolvers lacking support is deemed negligible.

<!-- In any case, regardless of "who moves first", resolution is never
disrupted, and changes to the set of UNIVERSAL algorithms do not
trigger overly conservative SERVFAIL responses.

Viktor:  This is not true.  If algorithms are prematurely deemed UNIVERSAL by
signers, and are not yet universall supported by resolvers, problems are sure
to happen.
-->

Resolvers dropping support for INSECURE algorithms (e.g. 7) without
implementing this specification will produce SERVFAIL responses for
multi-signer setups involving the disabled algorithm.  Implementation
of the new validation rules is thus advised as soon as support for an
algorithm is dropped.

# Acknowledgments

The author would like to thank Shumon Huque for early feedback on this proposal.
It was developed after discussions on the problem space with Edward Lewis, Jakob
Schlyter, Johan Stenstam, Steve Crocker, whose contributions where both
insightful and helpful.

{backmatter}

{#oldrules}
# Analysis of Original Specifications

## Signing Requirements

[@!RFC4035] Section 2.2 specifies the RRSIG presence requirements as follows:

    There MUST be an RRSIG for each RRset using at least one DNSKEY of
    each algorithm in the zone apex DNSKEY RRset.  The apex DNSKEY
    RRset itself MUST be signed by each algorithm appearing in the DS
    RRset located at the delegating parent (if any).

Further, Section 5.11 of [@!RFC6840] clarifies:

    A signed zone MUST include a DNSKEY for each algorithm present in
    the zone's DS RRset and expected trust anchors for the zone.

It may seem tempting to just relax this rule, without any further adjustments.
However, doing so is not safe depending on the algorithm combination involved.
In particular, when using an algorithm that is
not universally supported among the resolver population (such as
algorithm 7) together with a supported one (such as algorithm 13),
resolvers may return SERVFAIL under certain circumstances.

More explicitly, a zone that is using some algorithm as its sole
signing algorithm is (correctly) treated as insecure by resolvers
that do not support that algorithm.  However, when attempting to transfer the
domain to another DNS provider through a multi-signer setup with a
supported algorithm, affected resolvers presented with the unsupported signature
only will not be able to distinguish this situation from a downgrade-to-insecure
attack where the second signature has been stripped, and will return SERVFAIL.

Zone owners and signers thus would have to take great care to not leave a
validating resolver without a valid supported path when transitioning e.g. from
algorithm 7 to 13.

## Validator Requirements

In general (according to the old requirements), when a validating resolver
supporting any of the algorithms listed in a given zone's DS record or TA set
responds to a query without the CD flag set, it may not treat that zone as
insecure, but must return either validated data (AD=1) or RCODE=2
(SERVFAIL).  For this purpose, any valid path suffices; the validator
may not apply a "logical AND" approach to all advertised algorithms.

Accordingly, [@!RFC6840] Section 5.11 states:

    This requirement applies to servers, not validators.  Validators
    SHOULD accept any single valid path.  They SHOULD NOT insist that
    all algorithms signaled in the DS RRset work, and they MUST NOT
    insist that all algorithms signaled in the DNSKEY RRset work.

At first glance, the assertions that (1) the signer provide
signatures for all advertised algorithms while (2) the resolver shall
be content with just one seems somewhat contradictory.  However, the
role of the RRSIG rules is to ensure that the resolver will find a
valid path (using a "logical OR" strategy), regardless of which
particular algorithm(s) it supports, and thus be able to distinguish
reliably between "all is in order" (validated data) and a downgrade-to-insecure
attack (SERVFAIL).

With the new notion of UNIVERSAL algorithms, the same goal can be achieved with
less stringent signing and slightly modified validation rules (see above).


# Change History (to be removed before publication)

* draft-thomassen-dnsop-multialgo-01

> Editorial changes

> Add Viktor

* draft-thomassen-dnsop-multialgo-00

> Initial public draft.
