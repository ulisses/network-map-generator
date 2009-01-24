all:
	ghc -O2 -fvia-C -optc-O3 -funbox-strict-fields --make Main.hs -o stats

clean:
	rm *.o *.hi stats *~
