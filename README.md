# current-capa-code
My current code for capa PR #1944 (https://github.com/mandiant/capa/pull/1944)

In the default mode, the PR extracts domain names and IP addresses from a binary (or a file containing roughly an analysis of a binary). In "verbose" mode, the PR also extracts the functions that operate on the domain names or IP addresses. I have implemented these features so far for binaries (still need to extend them to the binary-analysis files). As you can see in the example below, this program uses a regex to match domain names. This can match with some weird string (though valid domain names - see the "verbose" mode example below). This program also applies some heuristic to check whether domains or URLs are used by networking WinAPI functions. (In "verbose" mode, "5y.n" is not operated on by a WinAPI function involved in networking.)

I'm also going to implement a "very verbose" mode, which will not only extract domain names and IP addresses, and the functions that operate on both, but also extract and print the functions all the way up the call stack to give users a sense of how those domain names and IP addresses are ultimately used.

Tested on Python 3.9.16 and capa 7.0.1.

# Example output

Default mode:

![image](https://github.com/aaronatp/current-capa-code/assets/58194911/4330fab5-b94a-42da-96c1-8ddb3dfd17fe)

Verbose mode:

![image](https://github.com/aaronatp/current-capa-code/assets/58194911/d7dc4ba4-18fb-40ac-951f-94176de27ea4)

# TODO:
Need to tidy up the rendering.
Very verbose mode for static analysis.
Default, verbose, and very verbose modes for dynamic analysis.
