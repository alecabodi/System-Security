### Steps to compile and run your project here ###

from terminal, go to Enclave_B directory and issue the following commands:

make clean
make SGX_MODE=SIM
./app

open another terminal window, go to Enclave_A directory and issue the following commands:

make clean
make SGX_MODE=SIM
./app

(socket communication is used on arbitrarily chosen port 8080: if such port is not available, simply change it on both Enclave_A and Enclave_B app files.)
(it maybe that, if several executions are issued in very short period of time, socket returns bind errors: simply wait a couple of second before starting a new execution of the protocol)



//use this to mark code regions as specified in the assignment sheet
/*************************
 * BEGIN [region that you're annotating, e.g. E_B decrypt challenge]
 *************************/
 <your code here>
/*************************
 * END [region that you're annotating, e.g. E_B decrypt challenge]
 *************************/
