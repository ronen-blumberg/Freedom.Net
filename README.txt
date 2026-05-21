================================================================================
                       KOLHAAM-NETWORK   0.1.2
        A test case in freedom. An unmoderated, anonymous, encrypted
        chat network in the spirit of the BBS and the early IRC days.
================================================================================


--------------------------------------------------------------------------------
0. THE MANIFESTO
--------------------------------------------------------------------------------

kolhaam-network is a test case in freedom.

It is small. It is unfinished. It is on purpose unmoderated. It does not
have a /kick command, it does not have a /ban command, it does not have a
"safety team", it does not have a "trust and safety policy", it does not
have a "verified" checkmark, it does not have an algorithm that picks what
you should see, it does not have an advertising budget, it does not have a
data-retention obligation, and it does not have a way to remember who you
are after you close the program.

What it has is this: a port, a keyphrase, a nickname, and a room.

If you know the keyphrase, you can join. If you do not, every byte on the
wire is encrypted with AES-256 in CBC mode under a key derived from that
phrase by 100,000 iterations of SHA-256, and you cannot read traffic - not
the operator of the server, not anyone watching the network, not the
person who is sitting at the table next to you in the cafe. The keyphrase
is the door. The keyphrase is the trust.

There is no account. There is no email confirmation. There is no captcha.
There is no biometric. There is no phone number. There is no "log in with
Google". You are whoever you say you are, for as long as you say it. If
you change your /nick the network forgets the old you. If you close the
program the network forgets you entirely.

That is the test case. The test is: can a tiny piece of software, a few
thousand lines of C and Python, let people who do not know each other find
each other and talk - without identity, without surveillance, without
moderation, without a company that owns the room? The answer used to be
yes, in 1985 and in 1993, and the answer is still yes.


--------------------------------------------------------------------------------
1. WHERE THIS COMES FROM
--------------------------------------------------------------------------------

In the 1980s, before the World Wide Web, before commercial dial-up, before
"online" was a verb people used at dinner, there was the BBS.

A BBS - a Bulletin Board System - was a computer in someone's spare
bedroom with a modem plugged into a phone line. You dialed it with your
own modem at 300, 1200, or 2400 baud, and the bedroom-computer answered.
It showed you a menu. It let you read messages other callers had left,
write your own, play a door game, download a file at a few hundred bytes
per second, leave a comment for the sysop. When you hung up, the next
caller dialed in. One line, one user at a time. The phone bill was real.
The community was small. You knew the sysop's first name. The sysop knew
yours - or whatever name you had given him.

That was the first version of this idea. A piece of software in someone's
house, that other people could connect to, and on which they could leave
words for each other to read. Nobody paid. Nobody owned it. The sysop
could pull the plug, but the sysop could also just leave it on.

In the 1990s, when the Internet replaced the telephone for these
connections, the same idea turned into IRC - Internet Relay Chat - and
into a hundred regional chat servers and webchat applets. You picked a
nick, you picked a channel, you typed, and other people on the same
channel saw it. There were no profile pictures. There were no follower
counts. The /who command told you who was in the room. The /me command
let you wave. The /msg command let you whisper to one person. If you did
not like a room, you typed /part, and you joined a different room, and
the room you left did not text you the next day asking why.

The early Internet was an unsupervised place that worked. The reason it
worked was not that everyone was nice. The reason it worked was that the
software did not pretend it could solve the problem of people, and so it
did not try to.

kolhaam-network is built in that tradition.


--------------------------------------------------------------------------------
2. WHAT KOLHAAM-NETWORK IS
--------------------------------------------------------------------------------

kolhaam-network is a small, light, minimalistic text-only chat network. It
consists of two programs:

    khn-server   the server. Runs on one machine, listens on one TCP
                 port, relays encrypted packets between connected users.
                 The server is a relay. It does not chat. It has no
                 nickname. It has no room of its own.

    khn-client   the client. Runs in a terminal or command prompt on
                 every user's machine. Connects to the server. Lets the
                 user join rooms, send messages, send files, whisper to
                 another user, change nickname, leave.

Both programs exist in two languages: C and Python. The C version is
fast. The Python version is slow on large file transfers but has no
build step. The two versions speak the same wire protocol byte for byte,
so any combination works: C client to C server, Python client to C
server, C client to Python server, Python client to Python server.

The server is anonymous to the network. It is identified only by its
host address and its port number. The keyphrase is shared out-of-band -
spoken on the phone, written on a piece of paper, posted on a private
forum, scribbled on a napkin. Anyone who has the address, port, and
keyphrase can join.


--------------------------------------------------------------------------------
3. FEATURES
--------------------------------------------------------------------------------

3.1 Encryption
    All wire traffic is AES-256-CBC encrypted. A fresh random 16-byte
    initialisation vector is sent with every packet. The 256-bit key is
    derived from the shared keyphrase via 100,000 iterations of SHA-256
    with the domain-separation tag "KolHaAmNet-v1". Without the
    keyphrase, no part of the conversation - text, nicknames, room
    names, file contents, who is talking to whom - is recoverable from
    the wire.

3.2 Anonymity
    There is no registration. There are no accounts. No email, no phone
    number, no password reset. You arrive with a nickname and a
    keyphrase; you leave when you close the window. The server does not
    persist any user record. If you reconnect with a new nickname, you
    are a new person.

3.3 Rooms
    Conversation happens in rooms. A room is created the moment the
    first user joins it and is destroyed the moment the last user
    leaves. Anyone can create a room by typing /join <name>. There is
    no list of "official" rooms.

        - Up to 25 users in a single room
        - Up to 10 rooms a single user can be in at once
        - Up to 100 rooms total on a single server
        - Up to 200 connected users total on a single server

3.4 Random assignment
    If you connect without specifying a nickname, the server picks a
    random one for you (e.g. "quiet_raven417"). If you connect without
    specifying a room, the server drops you into an existing
    non-full room or, if none exists, into a fresh "lobby_NNN".

3.5 Group chat
    Text messages typed in a room are broadcast to every user in that
    room. Every line is prefixed with a timestamp.

3.6 Private messages (DMs)
    The /msg command sends a one-to-one private text message to a
    specific user. The recipient does not need to be in the same room.
    DMs are encrypted on the wire like everything else; the server
    relays them but cannot read them only because... well, the server
    can read them, because the server has the keyphrase. The server
    cannot, however, leak them to the outside network. See section 9
    on what the encryption does and does not protect against.

3.7 Emotes
    The /me command produces a third-person action line, e.g.
        /me waves
    renders for everyone in the room as
        * alice waves *

3.8 Nickname changes
    The /nick command renames you. The new nickname is announced in
    every room you are currently in, and your client's log file
    rotates to a new file under the new name.

3.9 File transfer
    The /send command privately sends a file (up to 10 MB) to one
    specific user. The file path on disk must be absolute. The
    recipient's client saves the file in its current working directory
    under the original basename; if that name is taken, it appends
    .1, .2, ... before any failure. File payloads are encrypted on the
    wire like every other packet.

3.10 Listing
    The /who command lists the users currently in a given room
    (default: the room you are in right now).
    The /list command lists every room currently in existence on the
    server, with the user count for each. Secret rooms (see 3.13) are
    omitted from this listing.

3.11 Unmoderated by design
    There is no /kick. There is no /ban. There is no admin password.
    There is no operator account. There is no flag/report. There is
    no shadow-ban, mute, or content moderation. If you do not like a
    room, you /part it. If you do not like the people in a room, you
    /part it. If you do not like the server, you /quit and you point
    your client at a different one. The whole binary is small enough
    that running your own is realistic.

    The one personal accommodation is /ignore (see 3.15): a strictly
    client-side filter that hides another user's messages, DMs, and
    files from your own terminal. Nothing is sent over the wire, the
    ignored user is not told, and no one else's experience changes.
    It is the equivalent of looking the other way, not of silencing.

3.12 Per-user chat log
    On the client side, every event you see is also written to a
    plain-text log file in the current working directory, called
    kolhaam-net-<nickname>.log, in append mode. When you /nick, the
    log file rotates to the new name. The log is local to your machine
    and is never sent over the network.

3.13 Secret rooms
    A room whose name begins with "+" is a secret room. It does not
    appear in /list, and the server will never auto-place a random
    joiner into it. It has no other protection: anyone who knows the
    exact name can /join it, and once inside they can /who it. Think
    of it as a room with no signpost on the door, not a room with a
    lock.

    The first user to /join a "+" name creates the room; it is
    destroyed when the last user leaves, same as any other room.
    This is hiding-by-obscurity on purpose. It costs nothing, it
    requires no protocol change, and it is enough for most "let's
    keep this quiet" use cases. If you need real access control,
    run your own server and pick a keyphrase only the invited
    people know.

3.14 Cross-platform
    The C client and server both build on Linux x86_64 and on
    Windows i686 from one source file each. The Python client and
    server run on any system with Python 3.7 or newer, no third-party
    packages required.

3.15 Personal ignore list
    The /ignore command adds a nickname to a personal block list kept
    in your client's memory. While a nickname is on that list, your
    client silently drops every room message, every emote (/me), every
    private message (/msg), and every file (/send) that arrives with
    that nickname as sender. Nothing is written to your chat log for
    those packets either.

    /unignore removes a nickname from the list. /ignore with no
    argument prints the current list.

    Important properties:

      - It is purely local. No packet is sent to the server. Other
        users are not told. The server cannot tell. There is no
        moderation effect on anyone but you.
      - It is in-memory only. When you close the client the list
        is gone. Like everything else in kolhaam-network, the network
        does not remember.
      - Identity is just a nickname. If the user you ignored types
        /nick and picks a new one, your filter no longer matches.
        You will see them again under the new name and can /ignore
        that one too. This is a direct consequence of section 3.2
        (no accounts) and is honest about its limit.
      - Join, part, and nick-change announcements from an ignored
        user are still shown. Otherwise an ignored user could
        rename themselves and you would not know it was them.
      - Self-ignore is rejected. The list is capped at 64 entries
        (more than enough at 200 users per server).
      - Files from an ignored sender are dropped before being
        written to disk. This is the security-relevant case: an
        abusive user cannot drop files into your working directory
        just by virtue of knowing the keyphrase.


--------------------------------------------------------------------------------
4. COMMANDS
--------------------------------------------------------------------------------

Type a line of text and press Enter to send it to your current room.

    /join <room>            Join a room. If you are already in that
                            room, switch your "current room" to it.
                            Plain-text lines you type get sent to
                            your current room. Room names starting
                            with "+" are secret rooms (see 3.13);
                            they are hidden from /list but joinable
                            by anyone who knows the exact name.

    /part [<room>]          Leave a room. If you do not name one, you
                            leave your current room.

    /msg <nick> <text>      Send a private text message to one user.

    /send <nick> <path>     Send a file (<= 10 MB) to one user. The
                            path must be absolute (e.g. /home/me/a.png
                            or C:\Users\me\a.png).

    /me <action>            Emote in the current room.
                              /me waves   ->   * alice waves *

    /nick <newnick>         Change your nickname. The change is
                            announced in every room you are in.
                            Nicknames must be 1..31 characters, no
                            whitespace, no ":" or "," character.

    /who [<room>]           List users in a room. Defaults to current.

    /list                   List every room on the server with user
                            counts, e.g.   main(7), lounge(3), foo(1).
                            Secret rooms ("+"-prefixed) are not shown.

    /ignore [<nick>]        Hide room messages, emotes, DMs, and file
                            transfers from <nick>. Purely local, never
                            sent over the wire. With no argument,
                            prints the current ignore list. See 3.15.

    /unignore <nick>        Remove <nick> from your ignore list.

    /quit                   Disconnect from the server.

    /help                   Print this list.

    //text                  Send a literal line of text that starts
                            with "/". Useful for sending things like
                            "/usr/bin" as a chat message.


--------------------------------------------------------------------------------
5. BUILDING
--------------------------------------------------------------------------------

5.1 C, Linux x86_64

        gcc -O2 -Wall -Wextra -Wno-unused-parameter -o khn-server server.c -lpthread
        gcc -O2 -Wall -Wextra -Wno-unused-parameter -o khn-client client.c -lpthread

    Requires: gcc and libpthread (standard on every modern distro).

5.2 C, Windows i686 (cross-compiled from Linux)

        i686-w64-mingw32-gcc -O2 -o khn-server.exe server.c -lws2_32 -ladvapi32
        i686-w64-mingw32-gcc -O2 -o khn-client.exe client.c -lws2_32 -ladvapi32

    Requires: gcc-mingw-w64-i686. On Debian/Ubuntu:
        sudo apt install gcc-mingw-w64-i686

    The output .exe files are 32-bit Windows executables that run on
    Windows 7 and later.

5.3 Python (no build step)

        python3 server.py <port> <keyphrase>
        python3 client.py <server> <port> <keyphrase> [<nick>] [<room>]

    Requires: Python 3.7 or newer. No pip install of anything.
    Standard library only. Same wire protocol as the C build.


--------------------------------------------------------------------------------
6. RUNNING THE SERVER
--------------------------------------------------------------------------------

The server takes two arguments: the TCP port to listen on, and the
keyphrase that all clients will need.

    ./khn-server 6667 'midnight-in-the-garden'

or equivalently:

    python3 server.py 6667 'midnight-in-the-garden'

The keyphrase can contain spaces if you quote it. Pick a long one. The
key derivation deliberately takes a noticeable fraction of a second to
slow down anyone trying to brute-force it.

The server prints one log line per event (connect, disconnect, room
join, room part, file relay, nick rename) to stderr.

To stop the server cleanly, send it SIGINT (Ctrl-C) or SIGTERM. It will
close the listening socket and exit. Existing connections will then see
the socket close.


--------------------------------------------------------------------------------
7. RUNNING THE CLIENT
--------------------------------------------------------------------------------

The client takes the server address, the port, the keyphrase, and
optionally a nickname and a room:

    ./khn-client <server> <port> <keyphrase> [<nickname>] [<room>]

Examples:

    # Connect with everything specified.
    ./khn-client chat.example.com 6667 'midnight-in-the-garden' alice main

    # Connect and let the server pick a room for you.
    ./khn-client chat.example.com 6667 'midnight-in-the-garden' alice ""

    # Connect anonymously - server picks both nickname and room.
    ./khn-client chat.example.com 6667 'midnight-in-the-garden' "" ""

Pass an empty string ("") for nickname or room to have the server pick
a random one. Once connected, anything you type that does not start
with "/" goes to your current room. Commands start with "/" - see
section 4 for the full list.

To get a literal line of text starting with "/", prefix it with another
"/" - for example, "//hello" sends the chat line "/hello".

When you /join multiple rooms, your "current room" becomes the
most-recently-joined room. /join an existing room switches your current
room without rejoining. Type /part to leave the current room.


--------------------------------------------------------------------------------
8. THE WIRE PROTOCOL (BRIEFLY)
--------------------------------------------------------------------------------

Every TCP message is one encrypted "frame":

    [4 byte big-endian length N]  [16 byte IV]  [N - 16 bytes ciphertext]

The plaintext inside the ciphertext is:

    [1 byte packet type]          [packet payload]

Packet types are single ASCII letters:

    H  HELLO        client->server handshake; server->client handshake ack
    M  MSG          a chat line in a room
    O  EMOTE        an emote in a room (/me)
    D  DM           a private text message
    F  FILE         a private file transfer
    W  WHO          who-is-in-this-room request/response
    L  LIST         list-rooms request/response
    N  NICK         change-my-nickname request, and server's rename ack
    J  JOIN         join-a-room request, and server's join announcement
    T  PART         leave-a-room request, and server's part announcement
    X  SYS          server-originated room-scoped notice
    E  ERR          server-originated error notice to one client
    P  PING         heartbeat (sent occasionally, ignored on receive)
    Q  QUIT         client-originated polite disconnect

AES-256-CBC with PKCS#7 padding. The key is SHA-256 of the keyphrase
concatenated with the tag "KolHaAmNet-v1", then SHA-256'd 100,000 times
with the keyphrase mixed back in. Any reimplementation that uses the
same KDF and same packet layouts is interoperable.


--------------------------------------------------------------------------------
9. WHAT THE ENCRYPTION DOES AND DOES NOT PROTECT
--------------------------------------------------------------------------------

What it protects:

    - The contents of every message, DM, and file from every observer
      on the network between the client and the server.
    - The nicknames, room names, and command structure from every
      observer on the network.
    - The traffic from anyone who does not know the keyphrase.

What it does NOT protect:

    - The server operator and anyone who has the keyphrase. The server
      decrypts every frame in order to route it. The server has, by
      definition, the same key as every client.
    - Anyone else who legitimately knows the keyphrase. The keyphrase
      is a shared secret across the room; it is not a per-user
      identity.
    - Anyone who can read the client's chat log file on disk.
    - Side-channel information like packet timing, packet size,
      connection-uptime patterns. A determined observer can still tell
      that you are using kolhaam-network, when you are using it, and
      roughly how much traffic you are sending - they just can't read
      what you're saying.
    - Forward secrecy is not provided. If the keyphrase leaks tomorrow,
      a recorded session from today can be decrypted.

kolhaam-network is for casual privacy and casual anonymity in casual
chat. It is not a secure-messenger replacement for Signal or for
any threat model where the adversary is a nation-state. It is a way
to talk to a small group of people without inviting the rest of the
internet, and without trusting a third party who owns the server
to keep being nice.


--------------------------------------------------------------------------------
10. LIMITS
--------------------------------------------------------------------------------

    Max users per room              25
    Max rooms a single user can be in   10
    Max simultaneous clients on server  200
    Max rooms on server             100
    Max nickname length             31 characters (printable, no
                                    whitespace, ":", or ",")
    Max room name length            31 characters (same rules as nick)
    Max chat line                   1024 bytes (UTF-8 encoded)
    Max file size                   10 MB (10,485,760 bytes)

These are compile-time constants in the C source and module-level
constants in the Python source. If you want a bigger network, change
them and rebuild.


--------------------------------------------------------------------------------
11. PHILOSOPHY, ONE MORE TIME
--------------------------------------------------------------------------------

The point of kolhaam-network is not to be the best chat program. There are
plenty of better chat programs. The point is to be a chat program that
is small enough that one person can read all of its source code in an
afternoon, that has no dependency on any company or service, that
treats encryption as the price of admission rather than a premium
feature, and that does not require you to be a real person in order
to use it.

The point is that you can read it, understand it, build it, run it on
the cheapest VPS you can rent for $3 a month, and tell your friends
"the address is X, the port is Y, the keyphrase is Z". And that's the
whole protocol.

If the people in your room misbehave, you /part the room. If you do
not like the server, you run your own. If you do not like the protocol,
the source is in this directory.

We were all on Internet Relay Chat once. We were all on a 2400-baud
BBS once, or our parents were, or our grandparents were. Most of us
were happier there than we are now. This is a small attempt to
remember why.

================================================================================
                          end of MANIFESTO.txt
================================================================================
