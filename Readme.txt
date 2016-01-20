Here you can see how to compile and execute different test executable we created during the development process to see the funcionality of our implementation:

	1.Test inner product ammortized encryption
		Build by issuing: make ipdb-m-driver
it uses the class Ipdb in ipdb-m where we have the definition of the basic algorithms, developed through ipe-m, the basic inner product encryption implementation;

	2.Test inner product ammortized encryption with noise
		Build by issuing: make ipdbnoise-m-driver
it uses the class IpdbNoise in ipdb-m where we have the definition of the basic algorithms, developed through ipe-m, the basic inner product encryption implementation;

	3.Test inner product database (this is an all-in-one program that makes all the operation of the three main programs)
		Build by issuing: make SecureDB
The file that contains the rows has to be structured as follows:
	row1cell1#row1cell2#row1cell3#....#row1celln
	rowmcell1#rowncell2#rowncell3#....#rowmcelln
Example are in files 'row_120'(1 row, 120 cells), 'row_8'(1 row, 8 cells) and 'rows_8_40'(40 rows, 8 cells)
The query file has to be structured as 'query_8'(8 cells) file. That is:
	select1#select2#...
	where1
	where2
	
	where4
	...
	wheren
The new line character is considered like there's not a where condition for that cell.
