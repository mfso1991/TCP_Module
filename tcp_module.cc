// You will build this in project part B - this is merely a
// stub that does nothing but integrate into the stack

// For project parts A and B, an appropriate binary will be 
// copied over as part of the build process

/**********************************************************
 * Project 2
 * Yijia Cui, You Zhou
 **********************************************************/

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <stdlib.h>
#include <iostream>
#include "Minet.h"
#include "tcpstate.h"
#include "ip.h"
#include "constate.h"

using namespace std;

/* Create Packet to be sent */
void packetize(Packet& outP, ConnectionToStateMapping<TCPState>& conn2state, unsigned char flags, size_t n)
{
    IPHeader iph;
    TCPHeader tcph;
    iph.SetSourceIP(conn2state.connection.src);
    iph.SetDestIP(conn2state.connection.dest);
    iph.SetTotalLength(n + IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH);
    iph.SetProtocol(IP_PROTO_TCP);
    outP.PushFrontHeader(iph);
    
    tcph.SetSourcePort(conn2state.connection.srcport, outP);
    tcph.SetDestPort(conn2state.connection.destport, outP);
    tcph.SetHeaderLen(5, outP); //mask - can't be 20 
    tcph.SetFlags(flags, outP);
    tcph.SetAckNum(conn2state.state.GetLastRecvd(), outP);
    tcph.SetSeqNum(conn2state.state.GetLastSent(), outP);
    tcph.SetWinSize(conn2state.state.GetN(), outP);
    tcph.SetUrgentPtr(0, outP);
    tcph.ComputeChecksum(outP);
    outP.PushBackHeader(tcph);   
}

int main(int argc, char *argv[]) 
{
    MinetInit(MINET_TCP_MODULE);
    ConnectionList<TCPState> clist;
    MinetHandle mux = MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
    MinetHandle sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;
    if((mux == MINET_NOHANDLE) && MinetIsModuleInConfig(MINET_IP_MUX)) 
    {
        MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));
        return -1;
    }
    if((sock == MINET_NOHANDLE) && MinetIsModuleInConfig(MINET_SOCK_MODULE)) 
    {
        MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));
        return -1;
    }
    cerr << "tcp_module STUB VERSION handling tcp traffic.......\n";
    MinetSendToMonitor(MinetMonitoringEvent("HANDLING TCP TRAFFICS........"));

    MinetEvent event;
    double timeout = 1;

    while(MinetGetNextEvent(event, timeout) == 0) 
    {
        if((event.eventtype == MinetEvent::Dataflow) && (event.direction == MinetEvent::IN)) 
        {
            if(event.handle == mux) 
            {
                MinetSendToMonitor(MinetMonitoringEvent("IP PACKET ARRIVED."));

                /* store connection info */
                Connection conn; 
                Packet inP, outP; 

                     /* receiving packet and get TCP/IP headers*/
                MinetReceive(mux, inP);
                inP.ExtractHeaderFromPayload<TCPHeader>(TCPHeader::EstimateTCPHeaderLength(inP));
                TCPHeader TCPheader = inP.FindHeader(Headers::TCPHeader);
                 //checksum check before demux
                bool checksum = TCPheader.IsCorrectChecksum(inP);
                if(!checksum)
                    cerr<<"Checksum for TCP Header is false............................\n";
                IPHeader IPheader = inP.FindHeader(Headers::IPHeader);
              //  bool checksum_ok = IPheader.IsCorrectChecksum(inP);
              /*  if(!checksum_ok)
                    cerr<<"Checksum for IP Header is false............................\n";*/
            
                /* fliping the src-dest pair while preserving the protocol */
                IPheader.GetDestIP(conn.src);
                IPheader.GetSourceIP(conn.dest);
                IPheader.GetProtocol(conn.protocol);
                TCPheader.GetDestPort(conn.srcport);
                TCPheader.GetSourcePort(conn.destport);

                /* header information */
                unsigned int seq;
                unsigned int ack;
                unsigned char flags;
                unsigned short window_size;
                unsigned short ugt;
                unsigned char tcph_length;
                unsigned char iph_length;
                unsigned short data_size;
                unsigned short total_length;
                Buffer buffer;

                TCPheader.GetSeqNum(seq);
                TCPheader.GetAckNum(ack);
                TCPheader.GetFlags(flags);
                TCPheader.GetWinSize(window_size);
                TCPheader.GetUrgentPtr(ugt);
                TCPheader.GetHeaderLen(tcph_length);

                IPheader.GetHeaderLength(iph_length);
                IPheader.GetTotalLength(total_length);

                //do we need to mask it back? 
                data_size = total_length - iph_length * 4 - tcph_length * 4;
                buffer = inP.GetPayload().ExtractFront(data_size);               
               
                /* check whether we have that connection in the lsit */ 
                ConnectionList<TCPState>::iterator c = clist.FindMatching(conn);

                if(c != clist.end())
                {
                    unsigned short currentState;
                    currentState = (*c).state.GetState();

                    switch(currentState)
                    {
                        /* server mode - listen for SYN */ 
                        case LISTEN:
                        {
                            cerr<<"LISTEN state\n";
                            /* deal with passive open, check whether we have SYN. */
                            if(IS_SYN(flags))
                            {
                                /* UPDATE STATE */
                                (*c).connection = conn;
                                (*c).state.SetState(SYN_RCVD);
                                (*c).state.SetLastAcked((*c).state.last_sent);
                                (*c).state.SetLastRecvd(seq + 1);
                                (*c).state.last_sent++;
                                                        
                                /*set up flag as SYN and ACK */
                                flags = 0; /* restore */ 
                                SET_ACK(flags);
                                SET_SYN(flags);
                                
                                /* making packet */
                                packetize(outP, *c, flags, 0);
                                MinetSend(mux, outP);
                                sleep(2);
                                /* sending packet */
                                MinetSend(mux, outP);
                                cerr<<"\tSent SYN ACK Packet; Moving to SYN_RCVD\n";
                            }
                            break; 
                        }
                        /* Receive syn_rcvd, already have already sent out ACK and SYN, check whether have ACK - for server */
                        case SYN_RCVD:
                        {
                            cerr<<"SYN_RCVD state\n";
                            if(IS_ACK(flags))
                            {
                               (*c).state.SetState(ESTABLISHED); //connection established 
                               (*c).state.SetLastAcked(ack);
                               (*c).state.SetSendRwnd(window_size);
                               (*c).state.SetLastRecvd(seq + 1);
                               (*c).state.last_sent++;

                               cerr<<"\tReceived ACK Packet; Moving to Established\n";

                               SockRequestResponse repl;
                               repl.type = WRITE;
                               repl.connection = conn;
                               /* buffer is zero bytes */
                               repl.bytes = 0;
                               repl.error = EOK;
                               MinetSend(sock,repl);
                            }
                            break;
                        }

                        /* send syn already, waiting to receive syn and ack - for client */
                        case SYN_SENT:
                        {
                            cerr<<"SYN_SENT state\n";
                            /* if receive the ACK and SYN flags already - send ACK to the server. */
                            if(IS_SYN(flags) && IS_ACK(flags))
                            {
                                (*c).state.SetSendRwnd(window_size);
                                (*c).state.SetLastRecvd(seq + 1);
                                (*c).state.SetLastAcked(ack);
                                (*c).state.last_sent++;
                               
                                Packet outP; /* packet for ACK */
                                flags = 0; //restore
                                SET_ACK(flags); /* set flags for ACK. */
                                
                                packetize(outP, *c, flags, 0); /* create new packet send to server */
                                MinetSend(mux, outP);
                            
                                (*c).state.SetState(ESTABLISHED);
                                cerr<<"\tSent ACK Packet; Moving to Established\n";
                            
                                SockRequestResponse repl;
                                repl.type = WRITE;
                                repl.connection = (*c).connection;
                                /* buffer is zero bytes */
                                repl.bytes = 0;
                                repl.error = EOK;
                                MinetSend(sock,repl);
                            }
                            break;
                        }

                        case ESTABLISHED:
                        {
                            cerr<<"ESTABLISHED state\n";
                            //receive data and send ack 
                            if(IS_ACK(flags) && IS_PSH(flags))
                            {
                                   // cerr<< "receive packet.................\n";
                                    (*c).state.SetSendRwnd(window_size);
                                    (*c).state.SetLastRecvd(seq + data_size);
                                    (*c).state.SetLastAcked(ack);
                                    //cerr<<buffer.GetSize()<<endl;
                                    //(*c).state.last_sent = (*c).state.last_sent + 1;
                                    
                                    //put what we read into RecvBuffer
                                    (*c).state.RecvBuffer.AddBack(buffer);
                                    //reply to indicate how many bytes we read
                                    SockRequestResponse repl;
                                    repl.type = WRITE;
                                    repl.connection = conn;
                                    /* buffer is zero bytes */
                                    repl.data = (*c).state.RecvBuffer;
                                    repl.bytes = (*c).state.RecvBuffer.GetSize();
                                    repl.error = EOK;
                                    MinetSend(sock,repl);
                                    cerr<<"\tSent ACK Packet and delivered "<<data_size<<" bytes of data to socket"<<endl;

                                    flags = 0; //restore
                                    SET_ACK(flags); /* set flags for ACK. */
                                    //send out ack to indicate the recieve the packet
                                    packetize(outP, *c, flags, 0);
                                    MinetSend(mux, outP); 
                            }
                            else if(IS_FIN(flags)&& IS_ACK(flags))
                            {
                                //receive FIN, Send ACK, change the state to close_wait 
                                cerr<<"Receive FIN, start to close\n";
                                (*c).state.SetState(CLOSE_WAIT);
                                (*c).state.SetLastRecvd(seq + 1);
                              //  (*c).state.SetLastAcked(ack);
                               // (*c).state.SetLastRecvd(seq + 1);

                                flags = 0; //restore
                                SET_ACK(flags); /* set flags for ACK. */
                                //if(IS_ACK(flags))
                                    //cerr<<"ack\n";
                                //send out ack to indicate the recieve the packet
                                packetize(outP, *c, flags, 0);
                                MinetSend(mux, outP);
                                
                                (*c).state.SetState(LAST_ACK);
                                Packet P_2;
                                flags = 0; //restore
                                SET_FIN(flags); /* set flags for ACK. */
                                //if(IS_FIN(flags))
                                    //cerr<<"FIN\n";
                                //send out ack to indicate the recieve the packet
                                packetize(P_2, *c, flags, 0);
                                MinetSend(mux, P_2);
                                clist.erase(c);
                                 cerr<<"\tCLOSED Connection\n";
                                
                                SockRequestResponse repl;
                                repl.type = CLOSE;
                                repl.connection = (*c).connection;
                                /* buffer is zero bytes */
                                repl.bytes = 0;
                                repl.error = EOK;
                                MinetSend(sock,repl);
                            }
                            break;
                        }

                        case FIN_WAIT1:
                        {
                            break;
                        }

                        case FIN_WAIT2:
                        {
                            break;
                        }

                        case TIME_WAIT:
                        {
                            break;
                        }
                    }
                }
            } 
            if(event.handle == sock) 
            {
                MinetSendToMonitor(MinetMonitoringEvent("TCP REQ/REP ARRIVED."));
                SockRequestResponse req;
                SockRequestResponse repl;

                /* receive request */
                MinetReceive(sock, req);

                ConnectionList<TCPState>::iterator c = clist.FindMatching(req.connection);
     
                if(c == clist.end())
                {
                    //if it's not in the list before - new connection 
                    switch (req.type)
                    {
                        //client side - case connect - active open which corresponse CONNECT socket call 
                        //send SYN to remote side, initialize window size, generate window size 
                        case CONNECT:
                        {
                            cerr<<"CONNECT received for IPAddress(" <<req.connection.dest<<"):"<<req.connection.destport<<endl;

                            //send SYN to the server, state will be SYN_SENT
                            srand (time(NULL));
                            TCPState new_state(rand() % 10000000, SYN_SENT, 3);
                            ConnectionToStateMapping<TCPState> conn2state(req.connection, Time(), new_state, false);
                            clist.push_back(conn2state);
                            
                            Packet outP; //packet for SYN
                            
                            unsigned char flags = 0;
                            SET_SYN(flags);//set flags for SYN.
                           
                            packetize(outP, conn2state, flags, 0); //create new packet send to server 

                            MinetSend(mux, outP); //send out SYN packet
                            sleep(2);
                            MinetSend(mux, outP);

  
                            /* get from udp_module.cc */
                            repl.type=STATUS;
                            repl.connection=req.connection;
                            // buffer is zero bytes
                            repl.bytes = 0;
                            repl.error = EOK;
                            MinetSend(sock,repl);
                            break;
                        }
                        
                        //server side - case accept - passive open
                        //assume listen in default 
                        case ACCEPT:
                        {
                              //map state for the new connection, set time out and push connection back to the list 
                              cerr<<"ACCEPT received for Port "<<req.connection.srcport<<endl;
                              srand (time(NULL));
                              TCPState monitoring(rand() % 10000000, LISTEN, 3);
                              ConnectionToStateMapping<TCPState> conn2state(req.connection, Time(), monitoring, false);
                              clist.push_back(conn2state);
                              
                              /* get from udp_module.cc */
                              repl.type=STATUS;
                              repl.connection=req.connection;
                              // buffer is zero bytes
                              repl.bytes = 0;
                              repl.error = EOK;
                              MinetSend(sock,repl);
                              break; 
                        }

                        //other case will be handled later, only handle passive open and acive open in part 2a 
                        //get from udp_module.cc 
                        case STATUS:
                        {
                            //ignored, no response needed 
                            break;
                        }

                        case WRITE:
                        {
                            //write - handle later 
                            //no need to write 
                            break;
                        }

                        //default case 
                        default:
                        {
                            SockRequestResponse repl;
                            repl.type = STATUS;
                            repl.error = EWHAT;
                            MinetSend(sock,repl);
                            break;
                        }
                    }
                }
                else
                {
                    unsigned short currentState = (*c).state.GetState();
                    switch (req.type)
                    {
                        
                        case ACCEPT:
                            break;

                        case CONNECT:
                            break;

                        /*  send TCP data. The connection source is the local host and port, the
                        connection destination is the remote host and port, and the protocol is TCP. The
                        connection must refer to the result of a previously successful ACCEPT or
                        CONNECT request. The data Buffer contains the data to be sent, while the byte
                        count and error fields are ignored. The response is a STATUS with the same
                        connection, no data, the number of bytes actually queued by the TCP module,
                        and the error code. One WRITE may generate multiple TCP segments. It is the
                        responsibility of the Sock module or of the application to deal with WRITEs that
                        actually write fewer than the required number of bytes. */
                        case WRITE:
                        {
                            
                            cerr<<"Write Received";
                            //make sure it is from the last established state connection
                            if(currentState == ESTABLISHED)
                            {
                                //get the number required. 
                                unsigned bytes = req.data.GetSize();
                                unsigned queued = 0;
                                unsigned bytes_to_sent = 0;
                                
                                //check whether there is enough space to send out data
                                
                                if((*c).state.SendBuffer.GetSize() + req.data.GetSize() > (*c).state.TCP_BUFFER_SIZE)
                                { 
                                    //for flow control 
                                    repl.type = STATUS;
                                    repl.connection = req.connection;
                                    repl.bytes = 0;
                                    repl.error = EBUF_SPACE;
                                    MinetSend(sock, repl);
                                }
                                else
                                {
                                    //if send buffer is smaller than what we need to send - create one tcp packet
                                    //add the data at the back of send buffer
                                    //when is a good time to erase buffer? - when it's received? 
                                    (*c).state.SendBuffer.AddBack(req.data);
                                    
                                    bytes_to_sent = MIN_MACRO(TCP_MAXIMUM_SEGMENT_SIZE -IP_HEADER_BASE_LENGTH  - TCP_HEADER_BASE_LENGTH, bytes);

                                    //create payload 
                                    Packet outP(req.data.Extract(queued, queued + bytes_to_sent));
                
                                    unsigned char flags = 0;
                                    SET_ACK(flags);//set flags for ACK.
                                    SET_PSH(flags);//set flags for psh.
                            
                                    packetize(outP, *c, flags, bytes_to_sent);
                                    cerr<<"\tSent Packet with "<<bytes_to_sent<<" bytes of data"<<endl;
                                    MinetSend(mux, outP);
                                
                                    (*c).state.last_sent = (*c).state.last_sent + bytes_to_sent;
                                    queued += bytes_to_sent;
                                    bytes  -= bytes_to_sent;

                                    repl.type = STATUS;
                                    repl.connection = req.connection;
                                    repl.bytes = queued;
                                    repl.error = EOK;
                                    MinetSend(sock,repl);
                                }
                            }
                            break;
                        }
                            
                        /*
                        case FORWARD:
                        {*/
                            //forward matching packets. The TCP module ignores this message. A zero error STATUS will be returned
                            /* get from udp_module.cc */
                           /* repl.type = STATUS;
                            repl.connection = req.connection;
                            repl.error = EOK;
                            MinetSend(sock,repl);
                            break;
                        }*/

                        /* status update. This should be sent in response to TCP WRITEs. The
                        connection should match that in the WRITE. It is important that the byte count
                        actually reflects the number of bytes read from the WRITE. The TCP module
                        will resend the remaining bytes at some point in the future. */
                        
                        case STATUS:
                        {
                            
                            cerr<<"STATUS Received\n";
                            if(currentState == ESTABLISHED)
                            {
                                 // reflect the byte count from WRITE 
                                unsigned bytes = req.bytes;

                                //erase the part already read.
                                (*c).state.RecvBuffer.Erase(0, bytes);

                                // if there is still unsend data - resend request
                                //do I need to resend what's in the send buffer?
                                if((*c).state.RecvBuffer.GetSize() != 0)
                                {
                                    repl.type = WRITE;
                                    repl.connection = (*c).connection;
                                    repl.data = (*c).state.RecvBuffer;
                                    repl.bytes = (*c).state.RecvBuffer.GetSize();
                                    repl.error = EOK;
                                    MinetSend(sock,repl);
                                }
                            }
                            break;
                        }

                        /* close connection. The connection represents the connection to match on
                            and all other fields are ignored. If there is a matching connection, this will close it. 
                            Otherwise it is an error. A STATUS with the same connection and an error code will be returned */

                        // code borrowed from udp
                        // close when matched 
                        case CLOSE:
                        {   
                            cerr<<"CLOSE Received\n"; 
                            if(currentState == ESTABLISHED)
                            {
                                //set state to FIN_WAIT_1
                                (*c).state.SetState(FIN_WAIT1);
                                Packet outP;
                                unsigned char flags = 0;
                                SET_ACK(flags);//set flags for ACK.
                                SET_FIN(flags);//set flags for FIn.
                                packetize(outP, *c, flags, 0);

                                repl.type = STATUS;
                                repl.connection = (*c).connection;
                                repl.bytes = 0;
                                repl.error = EOK;
                                MinetSend(sock,repl);
                            }
                            break;
                        }

                        //default case 
                        default:
                        {
                            repl.type = STATUS;
                            repl.error = EWHAT;
                            MinetSend(sock,repl);
                            break;
                        }
                    }
                }
            }
        }
        if (event.eventtype == MinetEvent::Timeout) 
        {
            //time out 
        }
    }
    MinetDeinit();
    return 0;
}