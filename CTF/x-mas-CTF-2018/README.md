# CatanaGift [Rev 59 points]

### Chall's description
```
Something curious happened... a weird guy named Catana has created a secret message printer that uses a very complex algorithm.
You and Santa's MechaGnomes have to put your great minds togheter and get the program to print the message a bit faster.

Authors: littlewho + Gabies

```

#### File given for the chall
* [catana](./catana)

## Solution

```
$ file catana
catana: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ....
```

We start by executing the file, and nothing happens. The chall's description suggests that there's some algorithm to make more efficient,
so we get the original source code with the IDA pro decompiler.


```
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 v3; // rbx@5
  __int128 v4; // ax@11
  __int64 v5; // rcx@11
  char s[8]; // [sp+4h] [bp-2Ch]@9
  int l; // [sp+Ch] [bp-24h]@12
  int v9; // [sp+10h] [bp-20h]@9
  int k; // [sp+14h] [bp-1Ch]@7
  unsigned int j; // [sp+18h] [bp-18h]@3
  int i; // [sp+1Ch] [bp-14h]@1

  for ( i = 0; i <= 6; ++i )
  {
    for ( j = 0; (signed int)j <= 35; ++j )
    {
      v3 = arr_1_7row_36column[(signed int)j + 36LL * i];
      arr_2_question_mark[i] += not_fibo(j, 0, 0) * v3;
    }
  }
  for ( k = 0; k <= 6; ++k )
  {
    v9 = 0;
    memset(s, 0, 8uLL);
    while ( arr_2_question_mark[k] )
    {
      v4 = arr_2_question_mark[k];
      v5 = (unsigned __int8)(BYTE15(v4) + v4) - (*((_QWORD *)&v4 + 1) >> 56);
      LODWORD(v4) = v9++;
      s[(signed int)v4] = v5;
      arr_2_question_mark[k] /= 256LL;
    }
    for ( l = v9 - 1; l >= 0; --l )
      putchar(s[l]);
  }
  putchar(10);
  return 0LL;
}
```

So why this take so much time? the problem is the function not_fibo(j, 0, 0), which in pythonescue could be:

```
def not_fibo( a1,a2,a3):
 v6 = a3
 v7 = 0;
 if( (a2 != a1) or (a3 != a1)):
  if( a2 < a1):
   v4 = rec_one(a1,a2+1, a3)
   v7 = v4
  if((v6 < a1) and (v6 < a2)):
   v5 = rec_one(a1,a2,v6+1)
   v7 += v5
  result = v7
 else :
  result = 1
 #print(a1,a2,a3, "result: "+str(result))
 return result
```

So at this point i believe that i should rewrite this thing in a iterative way, but before i need to prove his arithmetic sequence formula.
Seems boring so instead i used dynamic programmaing + Branch and bound or smth like that but less complicated.

We suppose that this is an algorithm and so it will end.
Now we can represent the program that implements the algorithm as Control Flow Graph (CFG), and every execution for a particular input 'x.i' as an Control Flow Executed (CFE).
We want to prove, that, the CFE of f(x.i) is contained by the CFE of f(x.i+1).
At this point we analyze his input and output, searching similarity:

```
./rec_catana.py 1 | uniq -u
(1, 1, 1, 'result: 1')
(1, 1, 0, 'result: 1')
(1, 0, 0, 'result: 1')
1

./rec_catana.py 2 | uniq -u
(2, 2, 2, 'result: 1')
(2, 2, 1, 'result: 1')
(2, 2, 0, 'result: 1')
(2, 2, 2, 'result: 1')
(2, 2, 1, 'result: 1')
(2, 1, 1, 'result: 1')
(2, 1, 0, 'result: 2')
(2, 0, 0, 'result: 2')
2

./rec_catana.py 3 | uniq -u
(3, 3, 3, 'result: 1')
(3, 3, 2, 'result: 1')
(3, 3, 1, 'result: 1')
(3, 3, 0, 'result: 1')
(3, 3, 3, 'result: 1')
(3, 3, 2, 'result: 1')
(3, 3, 1, 'result: 1')
(3, 3, 3, 'result: 1')
(3, 3, 2, 'result: 1')
(3, 2, 2, 'result: 1')
(3, 2, 1, 'result: 2')
(3, 2, 0, 'result: 3')
(3, 3, 3, 'result: 1')
(3, 3, 2, 'result: 1')
(3, 3, 1, 'result: 1')
(3, 3, 3, 'result: 1')
(3, 3, 2, 'result: 1')
(3, 2, 2, 'result: 1')
(3, 2, 1, 'result: 2')
(3, 1, 1, 'result: 2')
(3, 1, 0, 'result: 5')
(3, 0, 0, 'result: 5')
5

./rec_catana.py 4 | uniq -u
(4, 4, 4, 'result: 1')
(4, 4, 3, 'result: 1')
...
(4, 1, 1, 'result: 5')
(4, 1, 0, 'result: 14')
(4, 0, 0, 'result: 14')
14

./rec_catana.py 5 | uniq -u
(5, 5, 5, 'result: 1')
(5, 5, 4, 'result: 1')
(5, 5, 3, 'result: 1')
(5, 5, 2, 'result: 1')
(5, 5, 1, 'result: 1')
...
(5, 1, 1, 'result: 14')
(5, 1, 0, 'result: 42')
(5, 0, 0, 'result: 42')
42
```

We stop here, and we find that is true that:
  f(2) = g(2,2,1) + g(2,1,1)
  f(3) = g(3,3,1) + g(3,2,1) + g(3,1,1)
  f(4) = g(4,4,1) + g(4,3,1) + g(4,2,1) + g(4,1,1)
  f(5) = g(5,5,1) + g(5,4,1) + g(5,3,1) + g(5,2,1) + g(5,1,1)

We suppose that this property is true for all the input.
Ok now we start working with g(x,y,z) and not more with f(x), and we note that;

```
g(x, y, z=1):
  if(x==y):
    return 1
  elif( x == y+1):
    return y
  elif( (y==1) or (y==2)):
    return g(x-1, x-1, 1)
  else 
    sum=0
    for yy in range(y-1, x, 1):
      som += g(x-1, yy, 1)
    return som
```

Now we take the original code, patch the executable by removing the not_fibo function and instead 
save directly to the address pointed by v3 the result. the location memory starts at offset 0x1060 and end at 0x1840.

```
      v3 = arr_1_7row_36column[(signed int)j + 36LL * i];
      arr_2_question_mark[i] += not_fibo(j, 0, 0) * v3;
```

The solution can be find to:
* [iter_catana.py](./iter_catana.py)
* [rec_catana.py](./rec_catana.py)

# The Flag:
    X-MAS{c474l4n_4nd_54n74_w3r3_600d_fr13nd5_1_7h1nk}

*edit: the eazy way was to know that these results are the beginning of the Catalan Suite, but i didn't know even what is the catalan suite, bad for me that i wasted 4 hours D:
 ref:https://github.com/elyrian/CTF_WriteUP/tree/master/2018/X-MAS_CTF/CatanaGift

