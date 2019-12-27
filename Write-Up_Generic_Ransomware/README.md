## Write-Up Generic Ransomware
> Jun 20 2019, Altin Thartori, github.com/tin-z

```
  .
  ├── ransom_zip.zip                                 # password "infected"
  .    ├── ransomware.exe                            # packed
  .    ├── ransomware-cleaned.exe                    # unpack 1, deepsea 4.1
  .    ├── output_ransomware-cleaned.exe             # unpack 2, xor hardcoded byte  
  .    └── output_ransomware-cleaned-cleaned.exe     # unpack 3, deepsea 4.1
  ├── cut_copybyte_andxor.py      
  ├── cut_copybyte_andxor_2.py
  ├── pgpkey_ransomware
  └── README.md
```


### Static analysis: 
 - file 'ransomware.exe' uploaded on virus total, found 20/60 virus tracking, now that i'm updating this 12/27/2019 is 48/60
 - launched strings command, no interesting pattern found
 - collect dependecies by depends.exe, also found mscoree.dll, but before, with strings command, we found "gdi32.dll"
 
 - launched exeinfope, it suggest deepsea obfuscator 4.1, more details:
  ```
    * Microsoft Visual C# / Basic.NET / MS Visual Basic 2005 [ Obfus/Crypted ]  - EP Token : 06000004
    * Obfuscated like ? :  DeepSea Obfuscator v4 / Ben-Mhenni-Protector / ?????
      -> Explore and analyze .NET assemblies with .NET Reflector v8.0 -
      www.red-gate.com/products/reflector - IF file is packed try .NET Generic
      unpacker from : www.quequero.org/Pack_Unpack - 
  ``` 

 - launched de4dot that correctly found deepsea 4.1, then i unpack it as 'ransomware-cleaned.exe'
 - reversing the unpacked binary with "Simple assemlby explorer" (SAEx) program, found that in class4, smethod_0() make it crash.. that's interesting
 - trying IDA + SAEx, then this is the interesting chain we found by using the xreferences:
       Class0.constructor -> class3.smethod_0-> class2.smethod_0() -> class1.smethod_2() -> class4.smethod_0() -> return byte[]
 
 - now we can use the best tool in the world, DnSpy, and so:
 
  1) inspecting class1.smethod_2()
        ```
        internal static void smethod_2()
        {
          Class0.assembly_0 =
          Class0.appDomain_0.Load(Class2.smethod_4(Class4.smethod_0(),
          Class2.smethod_1("ÆÈ!`~$-.+="))); 
        }
        ```
      a) An AppDomain provides a layer of isolation within a process. Everything
      you usually think of as "per program" (static variables etc) is actually
      per-AppDomain. This is useful for:
          -plugins (you can unload an AppDomain, but not an assembly within an AppDomain)
          -security (you can run a set of code with specific trust levels)
          -isolation (you can run different versions of assemblies etc)
      
      b) appdomain_0.Load, Loads the Assembly with a common object file format (COFF) based image containing an emitted Assembly.  
      
      c) class4.smethod_0() returns an array of byte with 143872 elements, while class2.smethod_1 returns an array of byte as the following "ÆÈ!`~$-.+=".ToCharArray()
      
      d) class2.smethod_4 :
       ```
          public static byte[] smethod_4(byte[] byte_0, byte[] byte_1)
          {
            for (int i = 0; i < byte_0.Length; i++)
            {
              int num = i;
              byte_0[num] ^= byte_1[i % byte_1.Length];
            }
            return byte_0;
          } 
       ```

      e) the class0.assembly_0 = .. instruction line, is a method from namespace System.Reflection, and so we are overwriting class0 with another base code

  2) inspecting class3.smethod_0()
        ```
        public static void smethod_0()
        {
          Class2.smethod_0();
          Class0.appDomain_0.AssemblyResolve += Class1.smethod_0;
        }
        ```
      a) AssemblyResolve, more here: https://docs.microsoft.com/en-us/dotnet/api/system.appdomain.assemblyresolve?view=netframework-4.8

      b) inspecting Class1.smethod_0 
            ```
            public static Assembly smethod_0(object object_0, ResolveEventArgs resolveEventArgs_0)
            {
              if (Class2.smethod_2(resolveEventArgs_0))
              {
                return null;
              }
              return Class0.assembly_0; //perfect!
            }
            ```

  3) inspecting class0.constructor
      ```
      static Class0()
      {
          try
          {
            Class0.smethod_0();
            Class3.smethod_0();
          }
          catch
          { }
      }
      
      public static void smethod_0()
		  {
			  for (int i = 0; i < 10; i++)
			  {
				  Thread.Sleep(1000);
			  }
			  Class0.appDomain_0 = AppDomain.CurrentDomain;
		  }
      ```


  4) Now we can write some script to do the class2.smethod_4 part, (in that time i wasn't able to use IDAPython),
    so we need to extract the byte array from class4.smethod_0() and class2.smethod_1
    Then we can directly inject the output and continue the unpacking routine
    
    cut_copybyte_andxor.py:
        ```
          #!/usr/bin/env python
          # coding=utf-8
          import sys,struct

          def main(args):
           filez = open(args[0], "rb")
           output = open("output_{0}".format( args[0] ), "wb")
           offset = int(args[1])
           till = int(args[2])
           key = \
           list( "\xc6\x00\xc8\x00\x21\x00\x60\x00\x7e\x00\x24\x00\x2d\x00\x2e\x00\x2b\x00\x3d\x00" )
           len_key = len(key)
           
           #print("#header") 
           #ret_raw = filez.read(offset)
           #output.write(ret_raw)

           print("#payload")
           filez.seek(offset)
           ret_raw = filez.read(till)
           out_raw = []
           for x in range(len(ret_raw)):
            v3,=struct.unpack("B", ret_raw[x])
            v3 ^= ord( key[x % len_key] )
            out_raw.append(struct.pack("B", v3))

           output.write("".join(out_raw))

           #print("#tail")
           #filez.seek(offset + till)
           #ret_raw = filez.read()
           #output.write(ret_raw)
           
           print(len(ret_raw))
           filez.close()
           output.close()


          if __name__ == "__main__":
            main( sys.argv[1:] )
        ```
    
 - So 2nd unpack, now we have 'output_ransomware-cleaned.exe', and the file extracted has signature name 'gdi32.dll', that is a graphic library, but in this case ain't it, of course
 - The executable is packed again with deepsea 4.1, now we have 'output_ransomware-cleaned-cleaned.exe'
 - uploaded on virus total, found 0/60 virus tracking, now that i'm updating this 12/27/2019 is 31/60, and the first time it was recognized as malware was in 2019-06-19 :)
 - trying IDA + DnsPy, found many interesting functions, in particular:

      - Program.constructor :
        ```
        static Program()
        {
          try
          {
            //return false, but before uses some delegates function to call sleep(2500)
            Class5.smethod_0(2500); 

            //return the executable name and then set his content to null by executing 'cmd.exe /C type null > ..'
            Class12.smethod_0(Environment.GetCommandLineArgs()[0]); 

            //return array of byte xored  .. we extracted later and seems it is a PGP secret key file
            AppDomain.CurrentDomain.AssemblyResolve += Program.<>c.<>9.method_0; 
          }
          catch (Exception)
          {
          }
        }
        ```

      - Program.<>c.<>9.method_0 :
        ```
       	internal Assembly method_0(object object_0, ResolveEventArgs resolveEventArgs_0)
        {
          Program.Class18 @class = new Program.Class18();
          @class.string_0 = new AssemblyName(resolveEventArgs_0.Name).Name + ".mdb";
          Assembly executingAssembly = Assembly.GetExecutingAssembly();
          string text = executingAssembly.GetManifestResourceNames().FirstOrDefault(new Func<string, bool>(@class.method_0));
          if (text == null)
          {
            return null;
          }
          Assembly result;
          using (Stream manifestResourceStream = executingAssembly.GetManifestResourceStream(text))
          {
            byte[] array = new byte[manifestResourceStream.Length];
            manifestResourceStream.Read(array, 0, array.Length);
            result = Assembly.Load(Program.D(array, new byte[]
            { 216, 37, 234, 75, 173, 181, 32, 27, 146, 14, 61, 8, byte.MaxValue, 62, 172, 235, 201, 198, 196, 81, 110, 116, 186, 4, 79, 
              56, 148, 95, 191, 209, 117, 169, 231, 2, 42 }));
          }
          return result;
        }
        ```
      
      - gdi32.VmDetector.VirtualMachineDetector  // self-explanatory, here we found many Romanian words
      
      - gdi32.ns0.* //40 classes, .. looking also those with .ctor()
    
 - We should look gdi32.StartClass, in fact that is the artifact of the malware
 


### Dynamic analysis 
 #TODO
