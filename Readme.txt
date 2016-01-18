1.Test inner product ammortized encryption
   Build by issuing
	make ipdb-m-driver
it uses the class Ipdb in ipdb-m where we have the definition of the basic algorithms, developed through ipe-m, the basic inner product encryption implementation

2.Test inner product ammortized encryption with noise
   Build by issuing
	make ipdbnoise-m-driver
it uses the class IpdbNoise in ipdb-m where we have the definition of the basic algorithms, developed through ipe-m, the basic inner product encryption implementation

3.Test inner product database (with the constraint that l<=n)
   Build by issuing
	make SecureDB
The file that contains the rows has to be structured as follows:
	row1cell1#cell2#cell3#....#celln
	row2cell1#cell2#cell3#....#celln
Example are in files 'row'(120 cells) and 'row2'(8 cells).
The query file has to be structured as 'query' file. That is:
	select1#select2#...
	where1
	where2
	
	where4
	...
	wheren
The white spaces are considered like there's not a where condition for that cell.
