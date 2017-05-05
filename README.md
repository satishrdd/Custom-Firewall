# Custom-Firewall
Created a firewall to filter packets based on custom rules.
Implemented a simple firewall with two network interface cards connecting to the external network (Internet) 
and the internal network that we secure.

To run it 
run the Client code in a host

Run the firewall code in a different host ,menu appears to play with the rules initially.

Then run the sender code in another host ,just need to check the ethernet frame to match mac addresses 
of sender and firewall and then select the type of packet to send and send it.Firewall will block it 
or allow it after verifying the rules.To improve the verification process I have optimized my algorithm 
to verify my merging interval of different rules and using cache to store the result of previous similar request.
