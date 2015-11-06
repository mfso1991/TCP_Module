// You will build this in project part B - this is merely a
// stub that does nothing but integrate into the stack

// For project parts A and B, an appropriate binary will be 
// copied over as part of the build process

/**********************************************************
 * Project 2A
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


#include <iostream>
#include "Minet.h"
#include "tcpstate.h"
#include "ip.h"
#include "constate.h"

using namespace std;

//not sure whether we need to re-write TCPState yet 

/*
struct TCPState 
{
    // need to write this
    std::ostream& Print(std::ostream &os) const 
    { 
        os << "TCPState()" ; 
        return os;
    }
    
    friend std::ostream& operator<<(std::ostream &os, const UDPState& L) 
    {
        return L.Print(os);
    }
};*/

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
	tcph.SetSeqNum(conn2state.state.GetLastSent() + 1, outP);
	tcph.SetWinSize(conn2state.state.GetN(), outP);
	tcph.SetUrgentPtr(0, outP);
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
                cerr<<"handle mux............................................................\n";
                MinetSendToMonitor(MinetMonitoringEvent("IP PACKET ARRIVED."));

                /* store connection info */
                Connection conn; 
                Packet inP, outP; 

                /* receiving packet and get TCP/IP headers*/
                MinetReceive(mux, inP);
                inP.ExtractHeaderFromPayload<TCPHeader>(TCPHeader::EstimateTCPHeaderLength(inP));
                TCPHeader TCPheader = inP.FindHeader(Headers::TCPHeader);
                IPHeader IPheader = inP.FindHeader(Headers::IPHeader);
            
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

                TCPheader.GetSeqNum(seq);
                TCPheader.GetAckNum(ack);
                TCPheader.GetFlags(flags);
                TCPheader.GetWinSize(window_size);
                
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
                            /* deal with passive open, check whether we have SYN. */
                            if(IS_SYN(flags))
                            {
                                /* UPDATE STATE */
                                (*c).connection = conn;
                                (*c).state.SetState(SYN_RCVD);
                                (*c).state.SetLastAcked((*c).state.last_sent);
                                (*c).state.SetLastRecvd(seq+1);
                                (*c).state.last_sent++;
                                                        
                                /*set up flag as SYN and ACK */
                                flags = 0; /* restore */ 
                                SET_ACK(flags);
                                SET_SYN(flags);
                                
                                /* making packet */
                                packetize(outP, *c, flags, 0); 
                                /* sending packet */
                                MinetSend(mux, outP);
                                sleep(2);
                                MinetSend(mux, outP);
                                /*
                                SockRequestResponse repl;
                                repl.type = STATUS;
                                repl.connection = conn;*/
                                /* buffer is zero bytes */
                                /*repl.bytes = 0;
                                repl.error = EOK;
                                MinetSend(sock,repl);*/
                            }
                            break; 
                        }
                        /* Receive syn_rcvd, already have already sent out ACK and SYN, check whether have ACK - for server */
                        case SYN_RCVD:
                        {
                            cerr<<"Final State of HandShaking ...............\n";
                            if(IS_ACK(flags))
                            {
                               (*c).state.SetState(ESTABLISHED); //connection established 
                               (*c).state.SetLastAcked(ack);
                               (*c).state.SetSendRwnd(window_size);
                               (*c).state.last_sent = seq + 1;

                               cerr<<"Connection Established ...............\n";

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
                            cerr<<"ACK to be sent ...........................\n";
                            /* if receive the ACK and SYN flags already - send ACK to the server. */
                            if(IS_SYN(flags) && IS_ACK(flags))
                            {
                                cerr<<"here send ack...............\n";
                                (*c).state.SetState(ESTABLISHED);
                                (*c).state.SetSendRwnd(window_size);
                                (*c).state.SetLastRecvd(seq + 1);
                                (*c).state.SetLastAcked(ack);
                                (*c).state.last_sent = (*c).state.last_sent + 1;
                               
                                Packet outP; /* packet for ACK */
                                flags = 0; //restore
                                SET_ACK(flags); /* set flags for ACK. */
                                
                                packetize(outP, *c, flags, 0); /* create new packet send to server */
                                MinetSend(mux, outP); //send out ACK package
                                /*sleep(2);
                                MinetSend(mux, outP);*/
                                
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

                        case ESTABLISHED:
                        {
                            
                           /*cerr<<"Connection writing...................................\n";*/
                              
                            /*packetize(outP, *c, flags, 0);
                            
                            MinetSend(mux,outP);*/
                            /*
                            //TCP_HEADER_LENGTH
                            SockRequestResponse repl;
                            // repl.type=SockRequestResponse::STATUS;
                            repl.type=STATUS;
                            repl.connection=(*c).connection;
                            repl.bytes=0;
                            repl.error=EOK;
                            MinetSend(sock,repl);*/
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
                            cerr<<"Active Open...............\n";

                            //send SYN to the server, state will be SYN_SENT
                            TCPState new_state(1, SYN_SENT, 3);
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
                              TCPState monitoring(1, LISTEN, 3);
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

                        //default case 
                        default:
                        {
                            /*SockRequestResponse repl;
                            repl.type = STATUS;
                            repl.error = EWHAT;
                            MinetSend(sock,repl);
                            break;*/
                        }
                    }
                }
                else
                {
                    
                    // if socket mode is write 
                    case WRITE:
                    {
                        cerr<<"Writing...................................\n";
                        unsigned bytes = MIN_MACRO(IP_PACKET_MAX_LENGTH-IP_HEADER_BASE_LENGTH-TCP_HEADER_BASE_LENGTH, req.data.GetSize());
                        // create the payload of the packet
                        // Packet p(req.data.ExtractFront(bytes));
                        Packet p;
                        unsigned char flags = 0;
                        SET_SYN(flags);
                        SET_PSH(flags);
                        packetize(p, *c, flags, bytes);
                        
                        MinetSend(mux,p);
                        
                        //TCP_HEADER_LENGTH
                        SockRequestResponse repl;
                        // repl.type=SockRequestResponse::STATUS;
                        repl.type=STATUS;
                        repl.connection=req.connection;;
                        repl.bytes=bytes;
                        repl.error=EOK;
                        MinetSend(sock,repl);
                        break;
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