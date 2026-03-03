---
layout: post
title: "Coin1 Pwnable.kr"
tags: [pwnablekr, binaryexploitation, C, coin1, Binary Search]
categories: [CTF]
image: /assets/img/posts/coin1.png
---
I will be walking through the pwnable.kr CTF called "coin1" which can be found [here](https://www.pwnable.kr/play.php). When clicking on the CTF (first one from the left on the second row - same image as the one attached to the article) you'll see it mentions playing a game.

[coin1 Game](#coin1-game)
- [Understanding The Game](#understanding-the-game)
- [What We Know](#what-we-know)

[The Flag And How To Get It](#the-flag-and-how-to-get-it)

# coin1 Game

## Understanding The Game
There isn't anything mentioned that we need to learn before we jump in. So let's just get right to it. Following the instructions on the site we are going to ssh into the machine with the following command: `ssh coin1@pwnable.kr -p2222` and once prompted provide the password provided by the CTF. Once in the machine we can run the `ls` command and see that we get 1 file back `readme`. If we try `cat readme` it returns with `nc 0 9007 to get flag!`. So we will have to connect to a port on the localhost for the game. If we run `nc 0 9007` we can take a look at the game.

![coin1 terminal](/assets/img/posts/coin1terminal.png)

There is no code to look at, but we do know the rules of the game. We need to find 100 counterfeit coins and every time we find a counterfeit coin it's a new game, basically. We have `N` number of coins and `C` number of chances. We need a way to search these numbers in a big enough chunk that will allow us to do it within the number of chances we have. Doing a little research I was able to find something called `Binary Search` which you can read about [here](https://www.geeksforgeeks.org/dsa/binary-search/). Here is a simple explanation:
```
N=10, counterfeit coin = 7

[1 2 3 4 5 6 7 8 9 10]

Search the first half of the array
[1 2 3 4 5] sending these numbers to the game sends back the number 50.

50 % 10 == 0 which means there is no counterfeit coin here. Move to the next half.

[6 7 8 9 10] is now the current search target. Search the first half of this array.

[6 7] sending this to the server returns 19. Counterfeit is here.

[6 7] is now the search target. Search the first half.

[6] sending this to the server returns 10.

[7] Search the second half and send this to the server.

[7] returns 9, it is the counterfeit.

Number of guesses: 4
```

## What We Know
Now that we understand the game, what do we know?

- We need to find 100 coins.
- Each time we find a coin it is a new game.
- Binary Search is what we should probably be using.

# The Flag And How To Get it
To complete this game you must use a script that will play the game for you using Binary Search. I've written my script in python which you can find on my Github [here](https://github.com/bpctf/pwnablekr-scripts/blob/main/coin1.py). I've commented the code thoroughly so I won't be explaining it, but you can copy that code. In the pwnable machine `cd /tmp` and `mkdir btmp` to create a new directory and then cd to it `cd btmp`. Once in there you can run `vim coin1.py` and then paste the code in. Once that is complete you can type `:wq` to exit and then call `python2 coin1.py` to run the code and get the flag!

![mistake chef](/assets/img/posts/coin1code.png)

![mistake solution](/assets/img/posts/coin1flag.png)

I've removed the flag, so go out there and get the flag yourself! 
