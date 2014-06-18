sslmux
======

Are you stuck behind a restrictive corporate firewall that won't let you access anything external except on ports 80 and 443?

Do you want to connect to your `sshd` service on port 22 from behind that restrictive firewall but can't?

Well, that's easy: just switch your `sshd` service to listen on port 443... except that won't work when you are also
running an HTTPS service on the same server on port 443.

Why can't we use port 443 for *both* HTTPS and SSH?

That was the idea behind [sslh](http://www.rutschle.net/tech/sslh.shtml) so I took it and reimplemented it!

Why?
====

Why did this need reimplementation, you ask? [sslh](http://www.rutschle.net/tech/sslh.shtml)'s C implementations
don't look to scale very well, and this fact is respectfully admitted in their
[github README](https://github.com/yrutschle/sslh/blob/master/README.md):

> If you have a very large site (tens of thousands of connections), you'll need a vapourware version that would
> use `libevent` or something like that.

I just so happen to know a language whose networking support is implemented in terms of `libevent` (at least in spirit):
[Go](http://golang.org/)!

The implementation in [Go](http://golang.org/) was surprisingly easy and required very little code. I would argue
it's probably more stable and scalable than [sslh](http://www.rutschle.net/tech/sslh.shtml)'s various implementations
in C (`fork`, `select`). I have yet to subject my implementation to a battery of rigorous tests but in practice it's
working very well.

I should note that I did not bother to reimplement all of [sslh](http://www.rutschle.net/tech/sslh.shtml)'s features.
I only implemented what I personally needed: SSH and HTTPS protocol detection and forwarding.

Ideally, I would like to have an OS primitive to simply hand off an `accept()`ed TCP connection from one process to
another instead of having to stupidly proxy all that traffic through a single process. Cut out the middle-man! If
anyone has any ideas to offer in this regard, I am all ears. I don't mind if the solution is Linux specific. I suspect
one would need a kernel module to accomplish this. FYI, I'm talking about exchanging a TCP connection between two
independent processes who have no knowledge of each other, and without requiring any side-channel communications e.g.
my sslmux process handing off its `accept()`ed connection to either `sshd` or `nginx` (HTTPS).
