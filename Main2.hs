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
import System.Environment

f nome = openOffline nome

callback1 :: PktHdr -> ByteString -> IO ()
callback1 pkt bs = fff $ unpack bs

main = do [nome] <- getArgs
          ff nome

ff :: String -> IO Int
ff nome = f nome >>= \x -> loopBS x (-1) callback1

fff :: [Word8] -> IO ()
fff bytes = let ethPacket = getPacketE bytes
            in case ethPacket of
                (Just p) -> case packType $ fromJust $ ethPacket of
                                 IPv6 -> IO.putStrLn "ipv6"
                                 IPv4 -> case protocol $ NE.content $ fromJust $ getPacketIPv4 bytes of
                                            TCP -> print $ fromJust $ getPacketTCP bytes
                                            UDP -> print $ fromJust $ getPacketUDP bytes
                                            ICMP -> print $ fromJust $ getPacketICMP bytes
                                            (NI4.Unknown w8) -> IO.putStrLn "unknownIP4"
                                 ARP -> print $ fromJust $ getPacketARP bytes
                                 (Ethernet i) -> print $ fromJust $ getPacketE bytes
                                 (NE.Unknown w16) -> print $ fromJust $ getPacketE bytes
                Nothing -> IO.putStrLn "otherE"

getPacket :: [Word8] -> InPacket
getPacket bytes = toInPack (listArray (0,Prelude.length bytes-1) bytes)

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
