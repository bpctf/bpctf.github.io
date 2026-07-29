---
layout: post
title: "Python Pitfalls: How to Secure Your Code Part 1"
tags: [python, web-security, secure coding]
categories: [Secure Coding]
image: /assets/img/posts/securecodelogo.png
---

Recently I watched a presentation by [Alex Brumen aka Brumens](https://brum3ns.github.io/) who is an ethical hacker, developer, bug bounty hunter, and currently a researcher enablement analyst at YesWeHack. Brumens gave a [presentation](https://youtu.be/F8KALVo4DPk) and wrote an [article](https://www.yeswehack.com/learn-bug-bounty/python-pitfalls-turning-developer-mistakes) on python's pitfalls and how to ethically exploit them. In this post we'll be using code snippets similar to those in Brumen's article and showcase how we can secure them to prevent these pitfalls. I would highly recommend you watch Brumen's presentation or read the article linked above.

## os.path.join
In VFX software development we used `os.path.join` often and I noticed in testing that supplying an absolute path would ignore previous paths used in the function. As Brumen showcases in his article looking at the documentation for `os.path.join` it states that exact issue: 
> If a segment is an absolute path (which on Windows requires both a drive and a root), then all previous segments are ignored and joining continues from the absolute path segment.
{: .prompt-danger }

Here is an example of a piece of vulnerable code that uses `os.path.join`.

![vuln join](/assets/img/posts/pythonjoinvuln.png)

So looking at our code example we give the user the option to supply a name to save a file that will write "Hello, world!" to a location on disc. Due to the fact that we're using `os.path.join` to join the `pwd` to the supplied file name by the user we are able to exploit it to save the file to any location on disc as shown in the screenshot below.

![vuln example](/assets/img/posts/pythonjoinex.png)
*The folder `hacks` is a symlink to the folder `python-pitfalls-hacks` one directory back.*

As you can see due to the use of `os.path.join` we were able to do path traversal to save the file one directory up from where the file should have been saved to. This means we would be able to save this file anywhere, assuming this code is called as `sudo`. One way this could be used maliciously is if a website or application allows the user to save a file on the server and the developer used an unsanitized `os.path.join` call, the user could then craft a cron file and upload it to `/etc/cron.d/filename` to get the malicious code to run as a cron job by the system. 

So how can we prevent this? Well, I'm sure there are a few ways to secure your code, but I'm going to show you the approach I take to secure the `os.path.join` call to prevent malicious attacks. In this code all we're doing is getting the absolute path of the file name, or in this case, the location the user is trying to save the file to, and then we're checking the common path and making sure it equals the `pwd` of where the script is called from.

![join sec1](/assets/img/posts/pythonjoinsec1.png)

This method does have 1 pitfall with folders that are symlinks. If the directory we're saving the file in has a symlink to another folder elsewhere on the system then this method would still allow us to write to that symlinked location and could be vulnerable. Using the code above we can replace `os.path.abspath(userPath)` with `os.path.realpath(userPath)` and that will resolve all symlinks to a real existing canonical path. With that change this is the new code:

![join sec2](/assets/img/posts/pythonjoinsec2.png)

![sec ex](/assets/img/posts/pythonjoinsecex.png)

## pathlib.joinpath
The `pathlib.joinpath` function is similar to `os.path.join` where calling it will append each provided argument in sequence. Here is a piece of vulnerable code, keeping it in line with what we used for `os.path.join`:

![pathlib vuln](/assets/img/posts/pythonpathlibvuln.png)

![pathlib vuln ex](/assets/img/posts/pathlibvulnex.png)
*The folder `hacks` is a symlink to the folder `python-pitfalls-hacks` one directory back.*

In the `os.path.join` example we used `os.path` to secure our code, so for this example I'm going to stick to `pathlib.Path` to secure our code. With that in-mind we have to change our code a bit to get appropriate paths to test against. The first call we're making is to `resolve()`. When we call `Path.joinpath` or create a `Path` object we call `resolve()` to make the path absolute and resolve any symlinks in the process. Then we use a function to check if the path we've resolved is relative to the `pwd` using `Path.is_relative_to(pwd)`. So the secure code will be:

![sec pathlib](/assets/img/posts/pythonpathlibsec.png)

![pathlib sec ex](/assets/img/posts/pythonpathlibsecex.png)

This ends the first part of Python Pitfalls: How to Secure Your Code. These functions are widely used in python projects and could be easily exploited by bad actors so knowing how to secure your code is vital to prevent it. Make sure to always read the documentation of functions you're using in production code!
