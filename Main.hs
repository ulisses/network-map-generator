{-#OPTIONS -XMultiParamTypeClasses -XFunctionalDependencies#-}
module Main where

import Network.Pcap
import Net.Packet
import qualified Net.PacketParsing as NPP
import Net.Ethernet
import Net.IPv4
import Net.ICMP
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

callback1 :: PktHdr -> ByteString -> IO ()
callback1 pkt bs = print $  ppp $ unpack bs
--callback1 pkt bs = print $ packType $ fromJust $ ppp $ unpack bs

ff = f >>= \x -> loopBS x (-1) callback1

p bytes = toInPack (listArray (0,Prelude.length bytes-1) bytes)

pp bytes = NPP.doParse $ p bytes :: Maybe (Net.Ethernet.Packet (Net.IPv4.Packet Net.ICMP.Packet))

ppp bytes = NPP.doParse $ p bytes:: Maybe (Net.Ethernet.Packet InPacket)
