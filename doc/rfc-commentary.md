# Comments on draft-ietf-ntp-roughtime-02

Author: Stuart Stock
Date  : 2020-06-14

## Introduction

I am the original creator and current maintainer of two Roughtime implementations:

  * Roughenough (Rust) https://github.com/int08h/roughenough
  * Nearenough (Java) https://github.com/int08h/nearenough

Have written deep-dive articles about the Roughtime protocol: 

  * https://int08h.com/post/to-catch-a-lying-timeserver/
  * https://int08h.com/post/roughtime-message-anatomy/
  
And operate the longest running publicly accessible (non-Googler) Roughtime server 
on the internet

  * roughtime.int08h.com:2002
  
I offer my comments on draft-ietf-ntp-roughtime-02 as someone well versed in the Roughtime 
protocol and intimately familiar with its implementation and trade-offs.

## Keep the "rough" in "Roughtime"

The authors of the original Roughtime protocol definition [roughtime] state that a 
deliberate goal of the Roughtime protocol was "...time synchronisation to within 10 
seconds of the correct time." Those authors go on to state that "[i]f you have 
_serious_ time synchronisation needs you‘ll want the machinery in NTP or even PTP..."

Addition of the DUT, DTAI, and LEAP fields run contrary to this design intent. These fields
provide time synchronization features that duplicate those in NTP and PTP. Precise time 
sync should be delegated to NTP and PTP and their ecosystems.

Simplicity of the Roughtime protocol encourages simple implementations. Simplicity
in implementation is a key to assurance that implementations are correct and secure. 
Increasing the number of fields and field types that must be implemented runs contrary 
to ease of implementation. Simplicity, and by extension security, should be a deliberate 
and top-of-mind design goal of the Roughtime standardization process.

Multiple existing IETF protocols address needs of highly accurate time synchronization 
and should be used where timing precision requires. Keep Roughtime "rough".

Suggestion: remove DUT, DTAI, and LEAP fields along with int32 type

## The LEAP field is not necessary 

Roughtime can handle leap seconds and time uncertainty/discontinuity complications without the 
addition of new tags/fields. The RADI field already provides a method for a Roughtime 
implementation to express time uncertainty in responses [draf02]: 

    The RADI tag value is a uint32 representing the server's estimate of
    the accuracy of MIDP in microseconds.  Servers MUST ensure that the
    true time is within (MIDP-RADI, MIDP+RADI) at the time they compose
    the response message.

In the case of a leap second, a Roughtime server can increase the value returned in 
the RADI field to account for the uncertainty introduced by a leap second. The increase 
in RADI value can persist as long as necessary (the duration of a leap second "smear" 
for example [AWS-smear] and [Google-smear]).
     
Suggestion: remove DUT, DTAI, and LEAP fields along with int32 type

## Introduction of a signed int32 type creates a new security risk 

The addition of the signed int32 field type (required to support the DUT, DTAI, and 
LEAP fields) exposes Roughtime implementations to a new *class* of software errors
around sign/unsigned conversions. 

The Common Weaknesses Enumeration Top 25 Most Dangerous Software Errors [CWE-TOP25] 
lists "Integer Overflow or Wraparound" as the #8 most frequent software weakness. The 
detail page on integer overflow [CWE-190] identifies signed/unsigned confusion, 
unintentional wrap-around, and lack of range checks as sources of software errors.

Introducing a signed integer type into Roughtime does not guarantee these issues
occur. However it does introduces an entirely new area of concern that would not
exist if these signed fields were omitted. 

Suggestion: remove DUT, DTAI, and LEAP fields along with int32 type

## Restore the 1024 byte minimum request size requirement

Draft 02 states that: 

    Responding to requests shorter than 1024 bytes is OPTIONAL 
    and servers MUST NOT send responses larger than the requests 
    they are replying to.

The minimum request size requirement exists to prevent a roughtime server from becoming
a DDoS amplifier [CF-DDoS]. A minimum request size of of 1024 bytes ensures that even 
a busy roughtime server signing a Merkle tree of 64 requests generates a response *smaller* 
than the 1024 byte request minimum (response would be 744 bytes, see [int08h]).

If requests smaller than 1024 bytes are permitted, how small could a request be? A valid 
Roughtime request *without* a PAD field would be 72 bytes long: 

     4 bytes number of fields 
     4 bytes NONC tag 
    64 bytes NONC value
    
Given that the *minimum* Server response size is 360 bytes [int08h], a minimal size request 
presents a DDoS attacker with a potential 5x gain in size.  

Making the minimum response size OPTIONAL requires Roughtime server operators to decide 
"how small is too small" and a wrong choice will create more DDoS amplifiers in the world.

Suggestion: mandate requests >= 1024 bytes

## Checking response vs. request size complicates server implementation

In Draft 02: 

    Responding to requests shorter than 1024 bytes is OPTIONAL 
    and servers MUST NOT send responses larger than the requests 
    they are replying to.

Roughtime servers can batch multiple requests into a single response making response 
size a function of server load/batching parameters plus concurrent requests. Roughtime 
Server implementations may gather or buffer client requests prior to constructing the 
response. 

"...servers MUST NOT send responses larger than the requests..." will require implementations
to perform additional tracking of per-request sizes and then compute the resulting response
size once the response *after* batch size has been determined. 

This is more complex and incurs additional processing compared to simply rejecting all 
requests <1024 bytes.

Suggestion: mandate requests >= 1024 bytes

## The "ROUGHTIM" packet format is redundant

The addition of the constant "ROUGHTIM" plus additional length field is redundant to 
the message format (which also has a length field). The value this additional 
packet format is not clear.

Suggestion: use "bare" Roughtime messages as the packet format 

## Stick with SHA-512; eliminate use of truncated SHA-512/256 

Truncated SHA-512/256 is performed by a) compute SHA-512, then b) truncate the result. 
The resulting computational effort of SHA-512 and SHA-512/256 is equivalent. 

The draft utilizes SHA-512/256 for its 32 byte output, as opposed to 64 bytes for
SHA-512. The motivation for this change is unclear and it complicates implementations
which now need two hashing primitives (SHA-512/256 initialization is different than SHA-512).

Suggestion: use SHA-512 throughout and drop any use of SHA-512/256

## References 

* [AWS-smear]     https://aws.amazon.com/blogs/aws/look-before-you-leap-the-coming-leap-second-and-aws/
* [CF-DDoS]       https://www.cloudflare.com/learning/ddos/ntp-amplification-ddos-attack/
* [CWE-190]       https://cwe.mitre.org/data/definitions/190.html
* [CWE-TOP25]     https://cwe.mitre.org/top25/archive/2019/2019_cwe_top25.html
* [draft02]       https://tools.ietf.org/html/draft-ietf-ntp-roughtime-02
* [Google-smear]  https://developers.google.com/time/smear
* [int08h]        https://int08h.com/post/to-catch-a-lying-timeserver/#keeping-response-sizes-compact
* [roughtime]     https://roughtime.googlesource.com/roughtime

