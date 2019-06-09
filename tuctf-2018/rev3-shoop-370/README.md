# Shoop [Reverse 370]:

### Chall's description
```
Difficulty: easy Black Hole Sun, won't you come
and put sunshine in my bag
I'm useless, but not for long
so whatcha whatcha whatcha want?

nc x.x.x.x 12345
```

#### File given for the chall
* [shoop](./shoop)

## Solution

The executable requires an input from stdin by using the read(0, stack_address, 0x16).
Then the stringZ is formatted as follows:
```python
	1) stringX = stringZ[::-1]
	2) stringZ = stringZ[len(stringX)/2:] + stringZ[:len(stringX)/2]
	3) stringZ = "".join([chr(ord(x) - 5 ) for x in stringZ ])
	4) stringX = stringZ
	5) then we do memcompare the stringX with the following string: "jmt_j]tm`q`t_j]mpjtf^"
	6) if the memcompare returns 0,then the system("/bin/cat flag") branch is executed
```

Apply the inverse function, using the string; "jmt_j]tm`q`t_j]mpjtf^"

output:

```
Gimme that good stuff: everybodyrockyourbody
Survey Says! jmt_j]tm`q`t_j]mpjtf^
That's right!
CFT{flag sz}
```

# The Flag:
	TUCTF{5w337_dr34m5_4r3_m4d3_0f_7h353}
