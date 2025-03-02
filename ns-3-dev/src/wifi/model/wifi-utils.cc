/*
 * Copyright (c) 2016
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Sébastien Deronne <sebastien.deronne@gmail.com>
 */

#include "wifi-utils.h"

#include "ctrl-headers.h"
#include "wifi-mac-header.h"
#include "wifi-mac-trailer.h"

#include "ns3/packet.h"

#include <cmath>

namespace ns3
{

const Time WIFI_TU = MicroSeconds(1024);

double
DbToRatio(double dB)
{
    return std::pow(10.0, 0.1 * dB);
}

double
DbmToW(double dBm)
{
    return std::pow(10.0, 0.1 * (dBm - 30.0));
}

double
WToDbm(double w)
{
    return 10.0 * std::log10(w) + 30.0;
}

double
RatioToDb(double ratio)
{
    return 10.0 * std::log10(ratio);
}

uint32_t
GetAckSize()
{
    static const uint32_t size = WifiMacHeader(WIFI_MAC_CTL_ACK).GetSize() + 4;

    return size;
}

uint32_t
GetBlockAckSize(BlockAckType type)
{
    WifiMacHeader hdr;
    hdr.SetType(WIFI_MAC_CTL_BACKRESP);
    CtrlBAckResponseHeader blockAck;
    blockAck.SetType(type);
    return hdr.GetSize() + blockAck.GetSerializedSize() + 4;
}

uint32_t
GetBlockAckRequestSize(BlockAckReqType type)
{
    WifiMacHeader hdr;
    hdr.SetType(WIFI_MAC_CTL_BACKREQ);
    CtrlBAckRequestHeader bar;
    bar.SetType(type);
    return hdr.GetSize() + bar.GetSerializedSize() + 4;
}

uint32_t
GetMuBarSize(std::list<BlockAckReqType> types)
{
    WifiMacHeader hdr;
    hdr.SetType(WIFI_MAC_CTL_TRIGGER);
    CtrlTriggerHeader trigger;
    trigger.SetType(TriggerFrameType::MU_BAR_TRIGGER);
    for (auto& t : types)
    {
        auto userInfo = trigger.AddUserInfoField();
        CtrlBAckRequestHeader bar;
        bar.SetType(t);
        userInfo.SetMuBarTriggerDepUserInfo(bar);
    }
    return hdr.GetSize() + trigger.GetSerializedSize() + 4;
}

uint32_t
GetRtsSize()
{
    static const uint32_t size = WifiMacHeader(WIFI_MAC_CTL_RTS).GetSize() + 4;

    return size;
}

uint32_t
GetCtsSize()
{
    static const uint32_t size = WifiMacHeader(WIFI_MAC_CTL_CTS).GetSize() + 4;

    return size;
}

bool
IsInWindow(uint16_t seq, uint16_t winstart, uint16_t winsize)
{
    return ((seq - winstart + 4096) % 4096) < winsize;
}

void
AddWifiMacTrailer(Ptr<Packet> packet)
{
    WifiMacTrailer fcs;
    packet->AddTrailer(fcs);
}

uint32_t
GetSize(Ptr<const Packet> packet, const WifiMacHeader* hdr, bool isAmpdu)
{
    uint32_t size;
    WifiMacTrailer fcs;
    if (isAmpdu)
    {
        size = packet->GetSize();
    }
    else
    {
        size = packet->GetSize() + hdr->GetSize() + fcs.GetSerializedSize();
    }
    return size;
}

bool
TidToLinkMappingValidForNegType1(const WifiTidLinkMapping& dlLinkMapping,
                                 const WifiTidLinkMapping& ulLinkMapping)
{
    if (dlLinkMapping.empty() && ulLinkMapping.empty())
    {
        // default mapping is valid
        return true;
    }

    if (dlLinkMapping.size() != 8 || ulLinkMapping.size() != 8)
    {
        // not all TIDs have been mapped
        return false;
    }

    const auto& linkSet = dlLinkMapping.cbegin()->second;

    for (const auto& linkMapping : {std::cref(dlLinkMapping), std::cref(ulLinkMapping)})
    {
        for (const auto& [tid, links] : linkMapping.get())
        {
            if (links != linkSet)
            {
                // distinct link sets
                return false;
            }
        }
    }

    return true;
}

} // namespace ns3
