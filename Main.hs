{-#OPTIONS -XMultiParamTypeClasses -XFunctionalDependencies -XEmptyDataDecls#-}
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
import Data.Map as M
import Data.Array.Vector as V
-- import Network.Pcap.Base
import Foreign.Marshal.Array (peekArray)
import IO
import Char
import Maybe

f = openOffline "snort.log"

--main = f >>= readAll

readAll :: PcapHandle -> IO [(PktHdr,ByteString)]
readAll ph =
    do (phd,bs') <- nextBS ph
       if phd == PktHdr 0 0 0 0 then return [] -- as in 'next' from 'Network.Pcap.Base'
         else do --print phd
                 res <- readAll ph
                 return ((phd,bs') : res)

getPkgs :: IO [InPacket]
getPkgs = f >>= readAll >>= return . Prelude.map (getPacket . B.unpack . snd)

a = getPkgs >>= sequence_ . Prelude.map (print . ffff)
aa = getPkgs >>= sequence_ . Prelude.map print . Prelude.filter (not . isNULL) . (Prelude.map ( ffff))

data PacoteM = NULL_NI4
             | NULL_NE
             | NULL_ETH
             | NULL_ARP
             | NULL_ICMP
             | PacoteTCP (NI4.Addr, NI4.Addr, NU.Port)
             | PacoteUDP (NI4.Addr, NI4.Addr, NU.Port)
             deriving Show

isNULL :: PacoteM -> Bool
isNULL (PacoteTCP _) = False
isNULL (PacoteUDP _) = False
isNULL _ = True

inToM :: [InPacket] -> [PacoteM]
inToM = Prelude.filter (not . isNULL) . Prelude.map ffff


class Info a where
    getIPSrc :: a -> NI4.Addr
    getIPDst :: a -> NI4.Addr
    getPortDst :: a -> NU.Port

instance Info PacoteM where
    getIPSrc (PacoteTCP (a,b,c)) = a
    getIPSrc (PacoteUDP (a,b,c)) = a
    
    getIPDst (PacoteTCP (a,b,c)) = b
    getIPDst (PacoteUDP (a,b,c)) = b
    
    getPortDst (PacoteTCP (a,b,c)) = c
    getPortDst (PacoteUDP (a,b,c)) = c

--PacoteTCP (192.168.74.242,193.136.19.96,Port 37602)

type Mapa = Map NU.Port [(NI4.Addr,NI4.Addr)] -- (src,dst)

main = getPkgs >>= print . aaa M.empty . inToM

aaa :: Info a => Mapa -> [a] -> Mapa
aaa m [] = m
aaa m (bytes:t) = let k = getPortDst bytes
                  in case M.lookup k m of
                     (Just a) -> let src = getIPSrc bytes
                                     dst = getIPDst bytes
                                 in case Prelude.elem (src,dst) a of
                                     True -> m `union` aaa m t
                                     False-> M.insert k ((src,dst) : (m M.! k)) m `union` aaa m t
                     Nothing -> M.insert k [(getIPSrc bytes, getIPDst bytes)] m `union` aaa m t

ffff :: InPacket -> PacoteM
ffff bytes = let ethPacket = getPacketE_ bytes
                in case ethPacket of
                    (Just p) -> case packType $ fromJust $ ethPacket of
                                    IPv4 -> case protocol $ NE.content $ fromJust $ getPacketIPv4_ bytes of
                                                TCP -> PacoteTCP (NI4.source $ NE.content $ fromJust $ getPacketUDP_ bytes,
                                                                  NI4.dest $ NE.content $ fromJust $ getPacketUDP_ bytes,
                                                                  NU.destPort $ NI4.content $ NE.content $ fromJust $ getPacketUDP_ bytes)
                                                UDP -> PacoteUDP (NI4.source $ NE.content $ fromJust $ getPacketUDP_ bytes,
                                                                  NI4.dest $ NE.content $ fromJust $ getPacketUDP_ bytes,
                                                                  NU.destPort $ NI4.content $ NE.content $ fromJust $ getPacketUDP_ bytes)
                                                ICMP -> NULL_ICMP
                                                (NI4.Unknown w8) -> NULL_NI4
                                    ARP -> NULL_ARP
                                    (Ethernet i) -> NULL_ETH
                                    (NE.Unknown w16) -> NULL_NE
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

-- callback1 :: Mapa -> PktHdr -> ByteString -> IO ()
-- callback1 mapa pkt bs = let lw8 = unpack bs
--                             f = fff mapa lw8
--                         in  
-- 

callback1 :: PktHdr -> ByteString -> IO ()
callback1 pkt bs = asas $ getPacket $ B.unpack bs

ff :: IO Int
ff = f >>= \x -> loopBS x (-1) callback1

asas :: InPacket -> PacoteM
asas bytes = let ethPacket = getPacketE_ bytes
                in case ethPacket of
                    (Just p) -> case packType $ fromJust $ ethPacket of
                                    IPv4 -> case protocol $ NE.content $ fromJust $ getPacketIPv4_ bytes of
                                                TCP -> PacoteTCP (NI4.source $ NE.content $ fromJust $ getPacketUDP_ bytes,
                                                                  NI4.dest $ NE.content $ fromJust $ getPacketUDP_ bytes,
                                                                  NU.destPort $ NI4.content $ NE.content $ fromJust $ getPacketUDP_ bytes)
                                                UDP -> PacoteUDP (NI4.source $ NE.content $ fromJust $ getPacketUDP_ bytes,
                                                                  NI4.dest $ NE.content $ fromJust $ getPacketUDP_ bytes,
                                                                  NU.destPort $ NI4.content $ NE.content $ fromJust $ getPacketUDP_ bytes)
                                                ICMP -> NULL_ICMP
                                                (NI4.Unknown w8) -> NULL_NI4
                                    ARP -> NULL_ARP
                                    (Ethernet i) -> NULL_ETH
                                    (NE.Unknown w16) -> NULL_NE
                    Nothing ->   error "otherE"

{-fff :: Mapa -> [Word8] -> Mapa
fff mapa bytes = let ethPacket = getPacketE bytes
                 in case ethPacket of
                    (Just p) -> case packType $ fromJust $ ethPacket of
                                     IPv4 -> case protocol $ NE.content $ fromJust $ getPacketIPv4 bytes of
                                                TCP -> M.singleton (NT.destPort $ NI4.content $ NE.content $ fromJust $ getPacketTCP bytes)
                                                                     [(NI4.source $ NE.content $ fromJust $ getPacketTCP bytes,
                                                                      NI4.dest $ NE.content $ fromJust $ getPacketTCP bytes)]-}
--                                                 UDP -> print (NI4.dest $ NE.content $ fromJust $ getPacketUDP bytes
--                                                              ,NU.destPort $ NI4.content $ NE.content $ fromJust $ getPacketUDP bytes)
--                                                 ICMP -> print $ getPacketTCP bytes
--                                                 (NI4.Unknown w8) -> error "unknownIP4"
--                                        ARP -> print $ getPacketARP bytes
--                                        (Ethernet i) -> print $ getPacketE bytes
--                                        (NE.Unknown w16) -> print $ getPacketE bytes
--                  Nothing ->   error "otherE"

--p :: [Word8] -> InPacket
getPacket :: [Word8] -> InPacket
getPacket bytes =  toInPack (listArray (0,Prelude.length bytes-1) bytes)

getPacketE bytes = doParse $ getPacket bytes :: Maybe (NE.Packet InPacket)
getPacketIPv4 bytes = doParse $ getPacket bytes :: Maybe (NE.Packet (NI4.Packet InPacket))
getPacketARP bytes = doParse $ getPacket bytes :: Maybe (NE.Packet NA.Packet)
--getPacketIPv6 bytes = doParse $ getPacket bytes :: Maybe (NE.Packet (NI6.Packet InPacket))

getPacketTCP :: [Word8] -> Maybe (NE.Packet (NI4.Packet (NT.Packet InPacket)))
getPacketTCP bytes = doParse $ getPacket bytes :: Maybe (NE.Packet (NI4.Packet (NT.Packet InPacket)))
getPacketUDP bytes = doParse $ getPacket bytes :: Maybe (NE.Packet (NI4.Packet (NU.Packet InPacket)))
getPacketICMP bytes = doParse $ getPacket bytes :: Maybe (NE.Packet (NI4.Packet NI.Packet))

--pp :: [Word8] -> Maybe (NT.Packet (NU.Packet NI.Packet))
pp bytes = doParse $ getPacket bytes :: Maybe (NE.Packet (NI4.Packet (NT.Packet NI.Packet)))

pppp bytes = doParse $ getPacket bytes :: Maybe (NE.Packet NA.Packet)

--pp bytes = doParse $ p bytes :: Maybe (NE.Packet (NI4.Packet NI.Packet))

ppp :: [Word8] -> Maybe (NE.Packet InPacket)
ppp bytes = doParse $ getPacket bytes:: Maybe (NE.Packet InPacket)
