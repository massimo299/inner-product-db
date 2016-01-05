Build by issuing
	make driver-b
it uses ipdb-d where we have the definition of the basic algorithms
the example constructed in driver-b consists of 
	- one row with 3 cells
		each cell contains an element of GT 
	- constructs the query for Cell 2	
there is a hack in the encryption that remembers the element of GT 
stored in Cell 2 and this is check with  the element of GT obtained in 
the main
