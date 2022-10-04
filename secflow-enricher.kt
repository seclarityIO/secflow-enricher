package io.seclarity.conversion.converters

import com.google.gson.Gson
import io.seclarity.conversion.models.EnrichedSecFlow
import io.seclarity.conversion.models.FlashRecord
import io.seclarity.conversion.models.SecFlow
import io.seclarity.conversion.models.SecFlowMarshal
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.math.BigDecimal
import java.math.BigInteger
import java.security.MessageDigest
import java.util.regex.Pattern

/**
@author Vladimir Budilov


The file should come in as follows:
{"hash":"569e7f0c6432c47f643046b9c77f597c0a5e410f"
,"trafficDate":"1601060272.439360"
,"fileName":"flipSnack_phishO365Portal_noTyping"
,"csecFlows":
[{"src":"192.168.100.224:49179",
"dst":"link.edgepilot.com:443",
"srcPkts":17,
srcBytes:3200,
"dstPkts":22,
"dstBytes":9996,
"relativeStart":3.4536,
"duration":16.9218,
"protocolInformation":"ICMP"
}]
}

We'll need to parse it to get out the hash, traffic date, file name,
and csecFlows. From there, all of the csecFlows should be turned into
FLASHes, packaged up into the proper JSON format, and sent back with
the hash, date, and filename as such:

{"hash":"569e7f0c6432c47f643046b9c77f597c0a5e410f"
,"trafficDate":"1601060272.439360"
,"fileName":"flipSnack_phishO365Portal_noTyping"
,"flashes":
[{"flash":"fa8d316dabc8f0a6a7a4439a0997756689799190",
"flowCat":"smallUpload",
"protocolInformation":"ICMP",
"src":"192.168.86.228:64360",
"dst":"142.250.82.71:19305",
"srcPkts":1217,
srcBytes:718697,
"dstPkts":751,
"dstBytes":46744,
"relativeStart":0.0200469,
.      "duration":39.6133
}]
}

 */
class SecFlowEnricherService {
    val log: Logger = LoggerFactory.getLogger("SecFlowEnricherService")

    val gson = Gson()

    private fun marshal(csecRaw: String): SecFlowMarshal {
        return gson.fromJson(csecRaw, SecFlowMarshal::class.java)
    }

    /**
     * Converts a raw secflow to an enriched secflow
     *
     * input: csec json
     * output: flash json
     */
    fun enrichRawSecflow(rawSecflow: String): FlashRecord {
        val rawSecflowJson = marshal(rawSecflow)

        return FlashRecord(
            hash = rawSecflowJson.hash,
            trafficDate = rawSecflowJson.trafficDate,
            fileName = rawSecflowJson.fileName,
            enrichedSecFlows = convertRawSecflowToEnriched(rawSecflowJson.fileName, rawSecflowJson.flashes)
        )
    }

    /**
     * Converts a csec flow to a flash
     *
     * input: csec flow arrayList
     * output: List of flashes
     *
     * todo: verify which parameters are required and non-null
     */
    private fun convertRawSecflowToEnriched(fileName: String, secFlow: ArrayList<SecFlow>): List<EnrichedSecFlow> {
        log.info("fileName=$fileName message=Entered convertRawSecflowToEnriched")

        val flows = mutableListOf<EnrichedSecFlow>()
        secFlow.forEach { flow ->

            // Ignore if IPv6 (temporary)
            /* something with just a port would have only 2 groups (the dest name and the port). But since IPv6 uses :
               as the octet delimiter, it must have more than 2 groups.
            */
            try {
                val likelyIPv6 = flow.dst.split(":").count() > 2
                if (likelyIPv6) {
                    log.debug("ignoring flow to likely IPv6 destination: $flow.dst")
                    return@forEach
                }
            } catch (e: Exception) {
                log.info("Couldn't figure out if the entry is IPv6: ${flow?.dst}")
            }


            // Parse Destination
            val dstPort = try {
                flow.dst.split(":")[1].toBigDecimal()
            } catch (e: Exception) {
                if (flow.protocolInformation.isNullOrEmpty()) {
                    return@forEach
                }
                (-1).toBigDecimal()
            }

            // Determine flowCat
            val flowCat = determineFlowCategory(flow, dstPort)
            val dst = determineDestination(flow.dst, flow.protocolInformation)

            flows.add(
                EnrichedSecFlow(
                    id = determineFlashFileHash(flowCat = flowCat, destination = dst),
                    flowCategory = flowCat,
                    protocolInformation = flow.protocolInformation,
                    destinationData = dst,
                    destinationNameSource = flow.destinationNameSource,
                    sourceData = flow.src,
                    sourceBytes = flow.srcBytes,
                    sourcePackets = flow.srcPkts,
                    destinationBytes = flow.dstBytes,
                    destinationPackets = flow.dstPkts,
                    relativeStart = flow.relativeStart,
                    duration = flow.duration
                )
            )
        }
        return flows
    }

    /**
     * Collect the full destination without its port (from the csecFlow example above, that would be “link.edgepilot.com”)
     * Collect the destination’s port value (“443” in the example above) OR its protocolInformation field if there is no port
     * Remove the highest stem from each destination (so “link.edgepilot.com” would be “edgepilot.com”)
     * Check if the full destination without its port is at least 3 sections long (“link.edgepilot.com” would be 3 long, while “google.com” would only be 2)
     * If it is at least 3 long, also chop off the top 2 stems for the destination (so “link.edgepilot.com” would be “com”); otherwise set that value to empty
     */
    private fun determineDestination(rawDestination: String, protocolInformation: String): String {

        val regionalCdns = hashSetOf(
            //"akamaiedge.net",
            //"akadns.net",
            //"cloudapp.net",
            //"omegacdn.net",
            "loki.delve.office.com",
            "fp.measure.office.com" //, there's still more to do here; only want to exclude '^[a-zA-Z0-9]{32}.fp....'
            //"trafficmanager.net",
            //"alphacdn.net"
        )
        val uniqueLinksCdns = hashSetOf(
            //"cloudfront.net",
            "1e100.net" //,
            //"v0cdn.net",
            //"phicdn.net"
        )
        //val uniqueLinksTwoLevelsDeep = hashSetOf("hwcdn.net")
        val googleCdns = hashSetOf("gvt1.com")
        val amazonCdns = hashSetOf(
            "signin.aws.amazon.com",
            "console.aws.amazon.com",
            "prod.pr.analytics.console.aws.a2z.com",
            "prod.pw.analytics.console.aws.a2z.com"
        )

        log.debug("rawDestination: $rawDestination")

        var port = ""
        val destHighestStemRemoved = if (rawDestination.contains(".")) {
            // Remove the highest stem from each destination (so “link.edgepilot.com” would be “edgepilot.com”)
            rawDestination.substringAfter(".")
        } else {
            log.error("The rawDestination is single-leafed -> ${rawDestination}")
            throw Exception("The rawDestination is single-leafed")

        }

        val destinationWithoutPortRaw = if (rawDestination.contains(":")) {
            port = rawDestination.substringAfter(":")

            rawDestination.substringBefore(":")
        } else
            rawDestination

        /*
            Check if the full destination without its port is at least 3 sections long
            (“link.edgepilot.com” would be 3 long, while “google.com” would only be 2)
            If it is at least 3 long, also chop off the top 2 stems for the destination (so “link.edgepilot.com” would be “com”);
            otherwise set that value to empty

         */
        val highestStemChoppedFromRawDestinationSplitOnPeriod = destHighestStemRemoved.split(".")
        log.debug("choppedFqdnSplitOnPeriod -> $highestStemChoppedFromRawDestinationSplitOnPeriod")

        var destTwoHighestStemsRemoved = ""
        if (highestStemChoppedFromRawDestinationSplitOnPeriod.size >= 3)
            highestStemChoppedFromRawDestinationSplitOnPeriod.forEachIndexed { index, leaf ->
                if (index > 1) {
                    destTwoHighestStemsRemoved += leaf
                }
            }

        var finalDestinationWithoutPort = destinationWithoutPortRaw
        if (regionalCdns.contains(destHighestStemRemoved))
            if (destHighestStemRemoved == "fp.measure.office.com")
                if (Pattern.matches(
                        "^[a-zA-Z0-9]{32}\\.fp\\.measure\\.office\\.com$",
                        destinationWithoutPortRaw
                    )
                ) /* Only truncate when it matches this value */
                    finalDestinationWithoutPort = "seclarityTruncated." + destHighestStemRemoved
                else
                    finalDestinationWithoutPort = destinationWithoutPortRaw
            else /* but if we're still in here and we have a different case */
                finalDestinationWithoutPort = "seclarityTruncated." + destHighestStemRemoved
        else if (uniqueLinksCdns.contains(destHighestStemRemoved))
            finalDestinationWithoutPort = "seclarityTruncated." + destHighestStemRemoved
        /*else if (uniqueLinksTwoLevelsDeep.contains(destTwoHighestStemsRemoved))
            finalDestinationWithoutPort = "seclarityTruncated." + destTwoHighestStemsRemoved
        Not needed right now.
         */
        else if (destinationWithoutPortRaw != "redirector.gvt1.com" && googleCdns.contains(destHighestStemRemoved))
            finalDestinationWithoutPort = "seclarityTruncated." + destHighestStemRemoved
        else if (amazonCdns.contains(destHighestStemRemoved) && !amazonCdns.contains(destinationWithoutPortRaw))
            finalDestinationWithoutPort = "seclarityTruncated." + destHighestStemRemoved

        if (finalDestinationWithoutPort.isNotEmpty())
            return finalDestinationWithoutPort + ":" + if (!port.isNullOrEmpty()) port else protocolInformation
        else return ""
    }

    /**
     * Collect the flow category (assigned above), dayZero (“07/04/2020”), and the destination (as modified by the
     * earlier portions of the algorithm). Concatenate them into a string separated by spaces
     * (so “link.edgepilot.com:443” would now become “smallDownload 07/04/2020 link.edgepilot.com:443”).
     * Hash the above string using the SHA-256 algorithm
     */
    private fun determineFlashFileHash(flowCat: String, dayZero: String = "07/04/2020", destination: String): String {

        return """$flowCat $dayZero $destination""".sha256()
    }

    private fun determineFlowCategory(flow: SecFlow, dstPort: BigDecimal): String {

        // Anything that has not been labeled should be labeled as unclassified.
        var flowCat = "unclassified"
        /*
            If there are 0 destination packets and dividing source bytes by source packets produces a value less than or equal to 66 (not enough payload to be meaningful; 66 is a magic number I’ve observed based on how systems react), label it as a failedConnection flow and move on to the next csecFlow.
         */
        if (flow.dstPkts == BigDecimal.ZERO &&
            ((flow.srcBytes / flow.srcPkts) <= BigDecimal.valueOf(66))
        )
            flowCat = "failedConnection"
        /*
            If there's just one side communicating, set it as unidirectional and move on.
         */
        else if (flow.dstPkts == BigDecimal.ZERO)
            flowCat = "unidirectional"
        /*
            If there is 1 destination packet, 1 source packet, and the port is 53, label it as a dnsQuery and move on to the next csecFlow.
         */
        else if (flow.dstPkts == BigDecimal.ONE &&
            flow.srcPkts == BigDecimal.ONE &&
            dstPort == BigDecimal.valueOf(53)
        )
            flowCat = "dnsQuery"
        /*
            If the port is 853, label it as a dotsQuery (DNS-over-TLS) and move on to the next csecFlow.
         */
        else if (dstPort == BigDecimal.valueOf(853))
            flowCat = "dotsQuery"
        /*
            If the difference between the number of source and destination packets is less than or equal to 2 (either side can be greater, hence absolute value), there is no more than 1 total byte transferred across both directions, and the duration of the session is at least 2 seconds, label it as a keepAlive (no real data was sent) and move on to the next csecFlow.
         */
        else if (((flow.dstPkts - flow.srcPkts).abs() <= BigDecimal.valueOf(2)) &&
            (flow.srcBytes + flow.dstBytes <= BigDecimal.ONE) &&
            flow.duration >= BigDecimal.valueOf(2)
        )
            flowCat = "keepAlive"
        /*
            If the port is 443, there is greater than 100 each of destination and source bytes, the total number of packets across both directions is fewer than 12, the total number of bytes across both directions is fewer than 2048 (common certificate and handshake size), and the duration is no more than half a second, label it as a tlsNegotionOnly and move on to the next csecFlow.
         */
        else if (dstPort == BigDecimal.valueOf(443) &&
            flow.dstBytes > BigDecimal.valueOf(100) &&
            flow.srcBytes > BigDecimal.valueOf(100) &&
            (flow.srcPkts + flow.dstPkts) < BigDecimal.valueOf(12) &&
            (flow.srcBytes + flow.dstBytes) < BigDecimal.valueOf(2048) &&
            flow.duration <= BigDecimal.valueOf(0.5)
        )
            flowCat = "tlsNegotiationOnly"
        /*
            If the destination has sent some bytes but the destination’s byte count is less than half of
            the source’s byte count (indicating that much more data was sent than received), and the
            source bytes are from 1 byte to ~1MB (a small amount of data), label it as a smallUpload
            and move on to the next csecFlow.
         */
        else if ((flow.dstBytes > BigDecimal.ZERO) &&
            (flow.dstBytes < (flow.srcBytes / BigDecimal.valueOf(2)) &&
                    (flow.srcBytes <= BigDecimal.valueOf(1000000)) &&
                    (flow.srcBytes > BigDecimal.ZERO))
        )
            flowCat = "smallUpload"
        /*
            If the destination has sent some bytes but the destination’s byte count is less than 30% of the source’s byte
            count (indicating that much more data was sent than received), and the source has sent at least ~1MB (at least
            a relatively large amount of data), label it as a largeUpload and move on to the next csecFlow.
         */
        else if (flow.dstBytes > BigDecimal.ZERO &&
            flow.dstBytes < (flow.srcBytes * BigDecimal.valueOf(.3)) &&
            flow.srcBytes > BigDecimal.valueOf(1000000)
        )
            flowCat = "largeUpload"

        /*
            If the duration of the session is no greater than 1 second, both the source and destination have sent some data,
            the source’s byte count is less than 50% of the destination’s byte count (indicating that much more data
            was received than sent), move into this decision logic to granularly label this csecFlow.
         */
        else if (flow.duration <= BigDecimal.ONE &&
            flow.srcBytes > BigDecimal.ZERO &&
            flow.dstBytes > BigDecimal.ZERO &&
            flow.srcBytes < (flow.dstBytes * BigDecimal.valueOf(.5))
        )
        /*
            If there are at least 2 destination packets per second and we have a "fullness" to the packets, move
            into deeper decision logic to granularly label this csecFlow.
        */
            if (flow.dstPkts >= BigDecimal.valueOf(2)
                && flow.dstBytes > (flow.dstPkts * BigDecimal.valueOf(.8) * BigDecimal.valueOf(1514))
            )
            /*
                If there's less than 10KB of data from destination, label as minorContentDownloadedQuickly and move
                onto the next csecFlow.
             */
                if (flow.dstBytes < BigDecimal.valueOf(10000))
                    flowCat = "minorContentDownloadedQuickly"
                /*
                    If there's ~ 10KB to less than ~ 1MB of data from destination, label as someContentDownloadedQuickly
                    and move onto the next csecFlow.
                 */
                else if (flow.dstBytes >= BigDecimal.valueOf(10000) && flow.dstBytes < BigDecimal.valueOf(1000000))
                    flowCat = "someContentDownloadedQuickly"
                else //at least ~ 1MB of data downloaded. Technically may want to differentiate between 2x vs. 3x data ratio, but will leave as-is for now
                    flowCat = "majorContentDownloadedQuickly"
            /*
                If there are less than 2 destination packets per second and/or we don't have very "full" packets, go into
                more granular labeling logic for this csecFlow.
            */
            else
            /*
               If there's less than 10KB of data from destination, label as minorContentDownloadedQuickly and move
               onto the next csecFlow.
            */
                if (flow.dstBytes < BigDecimal.valueOf(10000))
                    flowCat = "minorResourcesDownloadedQuickly"
                /*
                    If there's ~ 10KB to less than ~ 1MB of data from destination, label as someResourcestDownloadedQuickly
                    and move onto the next csecFlow.
                 */
                else if (flow.dstBytes >= BigDecimal.valueOf(10000) && flow.dstBytes < BigDecimal.valueOf(1000000))
                    flowCat = "someResourcesDownloadedQuickly"
                else //at least ~ 1MB of data downloaded. Technically may want to differentiate between 2x vs. 3x data ratio, but will leave as-is for now
                    flowCat = "majorResourcesDownloadedQuickly"
        /*
            If the duration of the session is between 1 and 10 seconds, both the source and destination have sent some data,
            the source’s byte count is less than 50% of the destination’s byte count (indicating that much more data
            was received than sent), move into this decision logic to granularly label this csecFlow.
         */
        else if (flow.duration > BigDecimal.ONE &&
            flow.duration < BigDecimal.TEN &&
            flow.srcBytes > BigDecimal.ZERO &&
            flow.dstBytes > BigDecimal.ZERO &&
            flow.srcBytes < (flow.dstBytes * BigDecimal.valueOf(.5))
        )
        /*
            If there are at least 2 destination packets per second and we have a "fullness" to the packets, move
                into deeper decision logic to granularly label this csecFlow.
        */
            if (flow.dstPkts >= (flow.duration * BigDecimal.valueOf(2))
                && flow.dstBytes > (flow.dstPkts * BigDecimal.valueOf(.8) * BigDecimal.valueOf(1514))
            )
            /*
                If there's less than 10KB of data from destination, label as minorContentDownloaded and move
                onto the next csecFlow.
             */
                if (flow.dstBytes < BigDecimal.valueOf(10000))
                    flowCat = "minorContentDownloaded"
                /*
                    If there's ~ 10KB to less than ~ 1MB of data from destination, label as someContentDownloaded
                    and move onto the next csecFlow.
                 */
                else if (flow.dstBytes >= BigDecimal.valueOf(10000) && flow.dstBytes < BigDecimal.valueOf(1000000))
                    flowCat = "someContentDownloaded"
                else //at least ~ 1MB of data downloaded. Technically may want to differentiate between 2x vs. 3x data ratio, but will leave as-is for now
                    flowCat = "majorContentDownloaded"
            /*
                If there are less than 2 destination packets per second, move into deeper decision logic to granularly
                label this csecFlow.
            */
            else
            /*
                If there's less than 10KB of data from destination, label as minorResourcesDownloaded and move
                onto the next csecFlow.
             */
                if (flow.dstBytes < BigDecimal.valueOf(10000))
                    flowCat = "minorResourcesDownloaded"
                /*
                    If there's ~ 10KB to less than ~ 1MB of data from destination, label as someResourcesDownloaded
                    and move onto the next csecFlow.
                 */
                else if (flow.dstBytes >= BigDecimal.valueOf(10000) && flow.dstBytes < BigDecimal.valueOf(1000000))
                    flowCat = "someResourcesDownloaded"
                else //at least ~ 1MB of data downloaded. Technically may want to differentiate between 2x vs. 3x data ratio, but will leave as-is for now
                    flowCat = "majorResourcesDownloaded"
        /*
            If the duration of the session is at least 10 seconds, both the source and destination have sent some data,
            the source’s byte count is less than 50% of the destination’s byte count (indicating that much more data
            was received than sent), move into this decision logic to granularly label this csecFlow.
         */
        else if (flow.duration >= BigDecimal.TEN &&
            flow.srcBytes > BigDecimal.ZERO &&
            flow.dstBytes > BigDecimal.ZERO &&
            flow.srcBytes < (flow.dstBytes * BigDecimal.valueOf(.5))
        )
        /*
            We don't care about how many packets per second or fullness for these, because the sessions are generally
            just open sessions that are caused by long-lived browser tabs/browsing behavior. So we'll just pay attention
            to amount of data transferred.
        */
        /*
            If there's less than 10KB of data from destination, label as minorDataDownloadedViaLongSession and move
            onto the next csecFlow.
         */
            if (flow.dstBytes < BigDecimal.valueOf(10000))
                flowCat = "minorDataDownloadedViaLongSession"
            /*
                If there's ~ 10KB to less than ~ 1MB of data from destination, label as someDataDownloadedViaLongSession
                and move onto the next csecFlow.
             */
            else if (flow.dstBytes >= BigDecimal.valueOf(10000) && flow.dstBytes < BigDecimal.valueOf(1000000))
                flowCat = "someDataDownloadedViaLongSession"
            else //at least ~ 1MB of data downloaded. Technically may want to differentiate between 2x vs. 3x data ratio, but will leave as-is for now
                flowCat = "majorDataDownloadedViaLongSession"

        /*
            Commented out because we've changed how we're handling this.
            If the duration of the session is at least 10 seconds, the destination has sent at least 1 packet, most
            packets are relatively “full” (identified here as 80% of MSS per packet), and the source’s byte count is
            less than 30% of the destination’s byte count (indicating that much more data was received than sent),
            label it as a continuousDownload and move on to the next csecFlow.
         */
        /*else if (flow.duration >= BigDecimal.valueOf(10) &&
            flow.dstPkts > BigDecimal.valueOf(0) &&
            flow.dstBytes > (flow.dstPkts * BigDecimal.valueOf(.8) * BigDecimal.valueOf(1514)) &&
            flow.srcBytes < (flow.dstBytes * BigDecimal.valueOf(.3))
        )
            flowCat = "continuousDownload"
        */

        /*
            Commented out because we've changed how we're handling this.
            If the duration is no greater than 1 second, both the source and destination have sent some data,
            the source’s byte count is less than 50% of the destination’s byte count (indicating that much more data
            was received than sent), and no more than ~ 1MB of data was received, label it as a briefDownload and move
            on to the next csecFlow.
         */
        /*else if (flow.duration <= BigDecimal.valueOf(1) &&
            /*flow.src == flow.dst &&*/ //Bug?
            flow.srcBytes < (flow.dstBytes * BigDecimal.valueOf(.5)) &&
            flow.srcBytes <= BigDecimal.valueOf(1000000)
        )
            flowCat = "briefDownload"
        */
        /*
            Commented out because we've changed how we're handling this.
            If everything of the above label is true EXCEPT that the duration is greater than 1 second,
            label it as a smallDownload and move on to the next csecFlow.
         */
        /*else if (flow.duration > BigDecimal.valueOf(1) &&
            /*flow.src == flow.dst &&*/
            flow.srcBytes < (flow.dstBytes * BigDecimal.valueOf(.5)) &&
            flow.srcBytes <= BigDecimal.valueOf(1000000)
        )
            flowCat = "smallDownload"
        */
        /*
            Commented out because we've changed how we're handling this.
            If both sides have sent some data, the destination has sent greater than ~ 1MB of data (a relatively
            large amount of data), and the source has sent less than 30% of the data that it has received from the
            destination (indicating that much more data was received than sent), label it as a largeDownload and
            move on to the next csecFlow.
         */
        /*else if (flow.srcBytes > BigDecimal.ZERO &&
            flow.dstBytes > BigDecimal.ZERO &&
            flow.dstBytes > BigDecimal.valueOf(1000000) &&
            flow.srcBytes < (flow.dstBytes * BigDecimal.valueOf(.3))
        )
            flowCat = "largeDownload"
        *//*
            If both sides have sent data (but have each sent less than ~ 10KB), both sides have sent packets,
             the duration is no greater than 10 seconds, and both sides have sent and received between 80% and 120% of
             the packets that were received and sent by the other side (meaning that the session is relatively
             balanced from the perspective of the number of packets sent/received), label it as a singleResourceLoaded
             and move on to the next csecFlow.
         */
        else if (flow.dstPkts > BigDecimal.ZERO &&
            flow.duration <= BigDecimal.TEN &&
            flow.dstBytes < BigDecimal.valueOf(10000) &&
            flow.srcBytes < BigDecimal.valueOf(10000) &&
            flow.srcBytes > BigDecimal.ZERO &&
            flow.dstBytes > BigDecimal.ZERO &&
            (
                    (flow.srcPkts in
                            (flow.dstPkts * BigDecimal.valueOf(.8))..(flow.dstPkts * BigDecimal.valueOf(1.2))
                            )
                            ||
                            (flow.dstPkts in
                                    (flow.srcPkts * BigDecimal.valueOf(.8))..(flow.srcPkts * BigDecimal.valueOf(1.2))
                                    )
                    )
        )
            flowCat = "singleResourceLoaded" //"minorResourceLoad"
        /*
            If the destination has sent data, the number of packets sent by the destination is at least as many
            as sent by the source, the source has sent greater than 10 bytes, and the duration is greater than 10
            seconds, label it as a continuousClientChannel and move on.
         */
        else if (flow.dstPkts >= flow.srcPkts &&
            flow.dstBytes == BigDecimal.ZERO &&
            flow.srcBytes > BigDecimal.valueOf(10) &&
            flow.dstPkts > BigDecimal.ZERO &&
            flow.duration > BigDecimal.valueOf(10)
        )
            flowCat = "continuousClientChannel"
        /*
            If the source has sent data, the number of packets sent by the source is at least as many as sent by the
            destination, the destination has sent greater than 10 bytes, and the duration is greater than 10 seconds,
            label it as a continuousServerChannel and move on to the next csecFlow.
         */
        else if (flow.srcPkts >= flow.dstPkts &&
            flow.srcBytes == BigDecimal.ZERO &&
            flow.dstBytes > BigDecimal.valueOf(10) &&
            flow.srcPkts > BigDecimal.ZERO &&
            flow.duration > BigDecimal.valueOf(10)
        )
            flowCat = "continuousServerChannel"

        /*
            If the duration is greater than 10 seconds, both sides have sent packets, and the number of packets
            sent/received is nearly identical (meaning that each side is essentially responding to each packet),
            label it as an asNeededChannel and move on to the next csecFlow.
         */
        else if (flow.duration > BigDecimal.valueOf(10) &&
            flow.srcPkts > BigDecimal.ZERO &&
            flow.dstPkts > BigDecimal.ZERO &&
            (flow.srcPkts - flow.dstPkts).abs() <= BigDecimal.valueOf(2)
        //Bug? flow.srcPkts in flow.dstPkts * BigDecimal.valueOf(.95)..flow.dstPkts * BigDecimal.valueOf(1.05)
        )
            flowCat = "asNeededChannel"
        /*
            If the number of packets sent by each side is no more than 2, the number of total bytes sent is 0, and the
            duration is less than 2 seconds, label it as a closedSession and move on to the next csecFlow.

         */
        else if (flow.dstPkts <= BigDecimal.valueOf(2) &&
            flow.srcPkts <= BigDecimal.valueOf(2) &&
            flow.dstBytes + flow.srcBytes == BigDecimal.ZERO &&
            flow.duration < BigDecimal.valueOf(2)
        )
            flowCat = "closedSession"


        return flowCat
    }

    fun String.sha256(): String {
        val md = MessageDigest.getInstance("SHA-256")
        return BigInteger(1, md.digest(toByteArray())).toString(16).padStart(32, '0')
    }
}
