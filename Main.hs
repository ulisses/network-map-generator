{-#OPTIONS -XMultiParamTypeClasses -XFunctionalDependencies#-}
module Main where

import Network.Pcap
import Net.Packet
import Net.PacketParsing as NPP
import Net.Ethernet as NE
import Net.IPv4 as NI4
import Net.ARP as NA
import Net.DHCP as ND
import Net.IPv6 as NI6
import Net.ICMP as NI
import Net.TCP as NT
import Net.UDP as NU
import Data.ByteString as B
import Data.ByteString.Internal
import Foreign.ForeignPtr
import Foreign.Ptr
import Data.Word
-- import Network.Pcap.Base
import Foreign.Marshal.Array (peekArray)
import IO
import Char
import Maybe

f = openOffline "snort.log"

main = f >>= readAll
readAll :: PcapHandle -> IO [(PktHdr,ByteString)]
readAll ph =
    do (phd,bs') <- nextBS ph
       if phd == PktHdr 0 0 0 0 then return [] -- as in 'next' from 'Network.Pcap.Base'
         else do --print phd
                 res <- readAll ph
                 return ((phd,bs') : res)

getPkgs = f >>= readAll >>= return . Prelude.map (getPacket . B.unpack . snd)

-- fazer uma classe com todas as operações em comum...
ffff bytes = let ethPacket = getPacketE_ bytes
                in case ethPacket of
                    (Just p) -> case packType $ fromJust $ ethPacket of
                                    IPv4 -> case protocol $ NE.content $ fromJust $ getPacketIPv4_ bytes of
                                                TCP -> print (NI4.dest $ NE.content $ fromJust $ getPacketTCP_ bytes
                                                            ,NT.destPort $ NI4.content $ NE.content $ fromJust $ getPacketTCP_ bytes)
                                                UDP -> print (NI4.dest $ NE.content $ fromJust $ getPacketUDP_ bytes
                                                            ,NU.destPort $ NI4.content $ NE.content $ fromJust $ getPacketUDP_ bytes)
                                                ICMP -> print $ getPacketTCP_ bytes
                                                (NI4.Unknown w8) -> error "unknownIP4"
                                    ARP -> print $ getPacketARP_ bytes
                                    (Ethernet i) -> print $ getPacketE_ bytes
                                    (NE.Unknown w16) -> print $ getPacketE_ bytes
                    Nothing ->   error "otherE"

getPacketE_ bytes = doParse bytes :: Maybe (NE.Packet InPacket)
getPacketIPv4_ bytes = doParse bytes :: Maybe (NE.Packet (NI4.Packet InPacket))
getPacketARP_ bytes = doParse bytes :: Maybe (NE.Packet NA.Packet)
--getPacketIPv6 bytes = doParse $ getPacket bytes :: Maybe (NE.Packet (NI6.Packet InPacket))

getPacketTCP_ bytes = doParse bytes :: Maybe (NE.Packet (NI4.Packet (NT.Packet InPacket)))
getPacketUDP_ bytes = doParse bytes :: Maybe (NE.Packet (NI4.Packet (NU.Packet InPacket)))
getPacketICMP_ bytes = doParse bytes :: Maybe (NE.Packet (NI4.Packet NI.Packet))

-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --

{-callback1 pkt bs =
    case pp $ unpack bs of
        Nothing -> case pppp $ unpack bs of
                        Nothing -> print ()
                        (Just p) -> print p
        (Just p) -> let src = NT.sourcePort $ NI4.content  $ NE.content p
                        dst = NT.destPort $ NI4.content  $ NE.content p
                    in print (src,dst)-}

callback1 :: PktHdr -> ByteString -> IO ()
callback1 pkt bs = fff $ unpack bs

ff :: IO Int
ff = f >>= \x -> loopBS x (1) callback1

fff :: [Word8] -> IO ()
fff bytes = let ethPacket = getPacketE bytes
            in case ethPacket of
                (Just p) -> case packType $ fromJust $ ethPacket of
                                 IPv4 -> case protocol $ NE.content $ fromJust $ getPacketIPv4 bytes of
                                            TCP -> print (NI4.dest $ NE.content $ fromJust $ getPacketTCP bytes
                                                         ,NT.destPort $ NI4.content $ NE.content $ fromJust $ getPacketTCP bytes)
                                            UDP -> print (NI4.dest $ NE.content $ fromJust $ getPacketUDP bytes
                                                         ,NU.destPort $ NI4.content $ NE.content $ fromJust $ getPacketUDP bytes)
                                            ICMP -> print $ getPacketTCP bytes
                                            (NI4.Unknown w8) -> error "unknownIP4"
                                 ARP -> print $ getPacketARP bytes
                                 (Ethernet i) -> print $ getPacketE bytes
                                 (NE.Unknown w16) -> print $ getPacketE bytes
                Nothing ->   error "otherE"

--p :: [Word8] -> InPacket
getPacket bytes =  toInPack (listArray (0,Prelude.length bytes-1) bytes)

getPacketE bytes = doParse $ getPacket bytes :: Maybe (NE.Packet InPacket)
getPacketIPv4 bytes = doParse $ getPacket bytes :: Maybe (NE.Packet (NI4.Packet InPacket))
getPacketARP bytes = doParse $ getPacket bytes :: Maybe (NE.Packet NA.Packet)
--getPacketIPv6 bytes = doParse $ getPacket bytes :: Maybe (NE.Packet (NI6.Packet InPacket))

getPacketTCP bytes = doParse $ getPacket bytes :: Maybe (NE.Packet (NI4.Packet (NT.Packet InPacket)))
getPacketUDP bytes = doParse $ getPacket bytes :: Maybe (NE.Packet (NI4.Packet (NU.Packet InPacket)))
getPacketICMP bytes = doParse $ getPacket bytes :: Maybe (NE.Packet (NI4.Packet NI.Packet))

--pp :: [Word8] -> Maybe (NT.Packet (NU.Packet NI.Packet))
pp bytes = doParse $ getPacket bytes :: Maybe (NE.Packet (NI4.Packet (NT.Packet NI.Packet)))

pppp bytes = doParse $ getPacket bytes :: Maybe (NE.Packet NA.Packet)

--pp bytes = doParse $ p bytes :: Maybe (NE.Packet (NI4.Packet NI.Packet))

ppp :: [Word8] -> Maybe (NE.Packet InPacket)
ppp bytes = doParse $ getPacket bytes:: Maybe (NE.Packet InPacket)
