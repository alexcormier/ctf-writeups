# Decipher the Prophecy

**CTF:** Pro CTF @ [Hackfest](https://hackfest.ca/) 2020

**Track:** Signal processing & Crypto

**Description:** The Gods are sending us mixed messages; We need to decipher the prophecy!

**Designer:** MaxWhite

## Context

We're sent to a simple looking web page that points us towards 3 pieces of information that we will need to find.

![THE GODS HAVE A MESSAGE FOR US](assets/web_page_1.jpg)

![CAN YOU HEAR THEM WHISPER YOUR KEY, THE SOUND OF 202 BELLS?](assets/web_page_2.jpg)

![THE HOBBITS ALSO DELIVERED A MYSTERIOUS TEXT AROUND HERE](assets/web_page_3.jpg)

So it looks like the Gods' message is going to be the prophecy that will yield our flags. We'll also need a key that's *whispered* by the Gods, but it won't be used to decrypt the prophecy directly, since we also need the Hobbits' mysterious text. Maybe the mysterious text could be an encapsulated key that will unlock the prophecy.

In any case, let's get to work retrieving these divine messages, keys and text, then we'll see how it all fits together.

## Getting the Gods' Message

> THE GODS HAVE A [MESSAGE](assets/encrypted_flag_pro.stl) FOR US

This first step seems rather easy: the message is directly linked! The problem is that it's an [STL](https://en.wikipedia.org/wiki/STL_(file_format)) file, a format to represent 3D objects, mainly for 3D printing. To see what exactly we're dealing with, we import it into Blender:

![Stick-looking message from the Gods](assets/blender_1.png)

It looks like a stick with this year's Hackfest logo... not very useful. But if there's nothing on the outside, what we're looking for has to be on the inside, right?

So pretend you know how to use Blender, find the X-Ray option and suddenly:

![Flag encrypted with AES-ECB inside the stick-looking message from the Gods](assets/blender_2.png)

Move the stick around a bit to get a clear view, and you get this encrypted flag:

```
------- BEGIN AES-ECB ENCRYPTED FLAG --------
bfjJ+iofjKTZAJNb8BQvuPdn8MTPs3TmE3ddyN5Opns=
-------- END AES-ECB ENCRYPTED FLAG ---------
```

## Getting the Key from the Gods' Whisper

> CAN YOU HEAR THEM WHISPER YOUR KEY, THE SOUND OF 202 BELLS?

The Gods' whisper isn't as obviously displayed as their message, so let's dive into the web page's [source](assets/index.html). We find the following snippet, after the footer:

```html
<video
    id="whisper"
    class="video-js"
    preload="auto"
    width="0"
    height="0"
    data-setup="{}"
    style="display: none;"
    autoplay
>
    <source src="https://e07afa893cb8.us-east-1.playback.live-video.net/api/video/v1/us-east-1.206175110892.channel.FdnBSOu5nfYj.m3u8" type="video/mp4" />
    <p class="vjs-no-js">
        To view this video please enable JavaScript, and consider upgrading to a
        web browser that
        <a href="https://videojs.com/html5-video-support/" target="_blank">supports HTML5 video</a>
    </p>
</video>
```

A live video, sounds like that might contain a whisper! Downloading a long enough sample of this never-ending video, for example with [youtube-dl](https://youtube-dl.org/), gives a repeating version of [this video](assets/bells.mp4).

Turn down the volume a tad and open this up in your preferred video player, you'll hear nice sounds reminiscent of the early days of the Internet: a modem. Looks like we've reached the signal processing part of this challenge!

So we have some modulated data that should contain our key, but how exactly was it modulated? Well, we've already seen the clue that'll tell us:

> THE SOUND OF 202 BELLS

Rings a bell? It's referring to the [Bell 202 modem](https://en.wikipedia.org/wiki/Bell_202_modem).

To demodulate this data, we turn to [minimodem](http://www.whence.com/minimodem/). A quick look through its options tells us that we need to use *1200* as the baud mode to emulate the Bell 202. So we convert the video file to a single-channel audio file and extract the data with minimodem:

```bash
ffmpeg -i bells.mp4 -ac 1 bells.flac && minimodem -f bells.flac 1200
```

[This key](assets/whisper.key) will be printed in the terminal.

## Getting the Hobbits' Mysterious Text

> THE HOBBITS ALSO DELIVERED A MYSTERIOUS TEXT AROUND HERE

The location of the hobbits' mysterious text is also not immediately obvious, so again, we look at the page's source. At the very bottom of the body, we find this script tag:

```html
<script src="assets/flag/ciphertext.js"></script>
```

Downloading this yields [this script](assets/ciphertext.js), clearly obfuscated with [JSFuck](http://www.jsfuck.com/). Running it doesn't produce anything, so we'll have to deobfuscate it. There are some tools online to help with this, but it's more fun to do it manually, isn't it? So let's do that.

The JSFuck website shows how the obfuscator builds various primitives like numbers and strings, functions and most importantly how it evaluates a string of code with the following:

```js
[]["filter"]["constructor"]( CODE )()
```

With this in mind, it's a fair assumption that our script will build a string of code and then evaluate it, so we should find this pattern at the beginning. Using an editor that can highlight matching brackets, we can confirm that the first 2046 characters follow this pattern, at least with regards to the brackets. We can extract what's inside the two square bracket pairs and evaluate them (e.g. with node) to confirm those also match:

```js
> (![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]
'flat'
> ([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]
'constructor'
```

Wait, shouldn't that say 'filter', not 'flat'? No, it looks like the JSFuck website is not up-to-date with all the changes that've been made to the library. `[]["filter"]` or `[]["flat"]` is just a way to retrieve a function. Exactly which function is used doesn't matter.

Evaluating the code block in the same way, we get the following:

```js
> (!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(+[![]]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]+(+(!+[]+!+[]+!+[]+[+!+[]]))[(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([]+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+((+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]]](!+[]+!+[]+!+[]+[!+[]+!+[]])+(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]
'return eval'
```

Ah, there's another layer to this obfuscation! Looking a little ahead, we see that the entire script matches this pattern:

```js
[]["flat"]["constructor"]("return eval")()( CODE )
```

This is functionally equivalent to:

```js
(function() { return eval })()( CODE )
```

Or simplified further:

```js
eval( CODE )
```

We can quickly observe that the code block we're after also follows the same pattern that's documented as the eval primitive on the JSFuck website. So we can extract the code the exact same way we did before, and we get this:

```js
return"\166ar\40\143i\160\150er\164e\170...\130\124\55\55\55\55\55\42"
```

Evaluate that string to replace all the escape codes with the corresponding characters, and you get `var ciphertext = "<ciphertext>"`, where `<ciphertext>` is the content of [this file](assets/ciphertext.enc). This is the hobbits' mysterious text!

## Putting It All Together

> YOU WILL NEED [THE HOBBITS' MYSTERIOUS TEXT] TOGETHER WITH THE GODS' WHISPERS TO COMPLETE THE KEY EXCHANGE AND FINALLY UNLOCK THE PROPHECY

We have an AES-encrypted flag, a private key and a ciphertext. It looks like our initial assumption was correct, and the ciphertext has to contain the encapsulated AES key. So let's start decrypting secrets!

### Determining the Key Encapsulation Algorithm

Ah, but first, we need to figure out what kind of private key we're dealing with. We don't have much information to stand on to make a guess, but we do have a couple hints.

First, the key is enormous. 19888 bytes. Post-quantum crypto algorithms typically use very large keys, so maybe we should look at those. Going through the [list](https://www.nist.gov/news-events/news/2020/07/pqc-standardization-process-third-round-candidate-announcement) of third round candidates for the NIST PQC Standardization Process, an internal alarm bell goes off when we reach [FrodoKEM](https://frodokem.org/). Of course the hobbits would've used Frodo!

So we know we need to use Frodo, but there are 6 different variants of the algorithm. Can we narrow down the possibilities? Some of these variants have different key sizes and we know our key is 19888 bytes in size, so table 5 of the [Frodo specification](https://frodokem.org/files/FrodoKEM-specification-20200930.pdf) tells us we need Frodo-640. We don't know whether we need the AES or SHAKE variant, but we can just try both when we get there.

### Decapsulating the Secret Key

We have a private key, an encapsulated key and a key encapsulation mechanism, now we need an implementation of this algorithm to decapsulate the key. Thankfully, a [reference implementation](https://github.com/Microsoft/PQCrypto-LWEKE) is available and it even includes a nice, simple python wrapper.

So we write a quick little python script to give us the two candidate keys:

```python
from base64 import b64decode
from pathlib import Path
from sys import argv
from frodokem import FrodoKEM

if __name__ == '__main__':

    sk = Path(argv[1]).read_text().strip()
    sk = sk[len('-----BEGIN CLIENT PRIVATE KEY-----'):-(1 + len('-----END CLIENT PRIVATE KEY-----'))]
    sk = sk.replace(' ', '').replace('\n', '')
    sk = b64decode(sk)

    ct = Path(argv[2]).read_text().strip()
    ct = ct[len('-----BEGIN CIPHERTEXT-----'):-(1 + len('-----END CIPHERTEXT-----'))]
    ct = ct.replace(' ', '').replace('\n', '')
    ct = b64decode(ct)

    for kem in [FrodoKEM('FrodoKEM-640-AES'), FrodoKEM('FrodoKEM-640-SHAKE')]:
        ss_d = kem.kem_decaps(sk, ct)
        print(ss_d.hex())
```

Run it:

```bash
$ python decaps.py whisper.key ciphertext.enc
90adb2bf5f846005e491930616222d7e
6a040bc1a0c6f8c51aaa724dcd9485ac
```

### Decrypting the Gods' Message

The final step is very simple: we have a ciphertext encrypted with AES-ECB along with two candidate keys, so we just need to try decrypting the message with both keys and see what we get. Again, we write a quick python script:

```python
from base64 import b64decode
from codecs import decode
from pathlib import Path
from sys import argv
from Crypto.Cipher import AES

if __name__ == '__main__':

    ct = Path(argv[1]).read_text().strip()
    ct = ct[len('------- BEGIN AES-ECB ENCRYPTED FLAG --------'):-(1 + len('-------- END AES-ECB ENCRYPTED FLAG ---------'))]
    ct = ct.replace(' ', '').replace('\n', '')
    ct = b64decode(ct)

    for key in argv[2:]:
        key = decode(key, 'hex')
        aes = AES.new(key, AES.MODE_ECB)
        flag = aes.decrypt(ct)
        print(flag)
```

Run it:

```bash
$ python decrypt.py flag.enc 90adb2bf5f846005e491930616222d7e 6a040bc1a0c6f8c51aaa724dcd9485ac
b'HF-aCPKGzfnJktQdfi7VTjuKxEuAw8Z7'
b'\x8c\xfc\x9d\xac\xd5\x03D\xdcAp\xd4\x9f\xc0.\xf9\xde\xb3w~;21\xe4\xc0\xf6#\xfa\x84\xfb\x99\xc9+'
```

And there we have it, the Gods' message was **HF-aCPKGzfnJktQdfi7VTjuKxEuAw8Z7**!