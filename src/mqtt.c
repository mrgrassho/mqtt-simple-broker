#include <stdlib.h>
#include <string.h>
#include "mqtt.h"
#include "pack.h"

static size_t unpack_mqtt_connect(const unsigned char *,
                                  union mqtt_header *,
                                  union mqtt_packet *);
static size_t unpack_mqtt_publish(const unsigned char *,
                                  union mqtt_header *,
                                  union mqtt_packet *);
static size_t unpack_mqtt_subscribe(const unsigned char *,
                                    union mqtt_header *,
                                    union mqtt_packet *);
static size_t unpack_mqtt_unsubscribe(const unsigned char *,
                                      union mqtt_header *,
                                      union mqtt_packet *);
static size_t unpack_mqtt_ack(const unsigned char *,
                              union mqtt_header *,
                              union mqtt_packet *);
static unsigned char *pack_mqtt_header(const union mqtt_header *);
static unsigned char *pack_mqtt_ack(const union mqtt_packet *);
static unsigned char *pack_mqtt_connack(const union mqtt_packet *);
static unsigned char *pack_mqtt_suback(const union mqtt_packet *);
static unsigned char *pack_mqtt_publish(const union mqtt_packet *);

/*
 * MQTT v3.1.1 standard, Remaining length field on the fixed header can be at
 * most 4 bytes.
 */
static const int MAX_LEN_BYTES = 4;

/*
 * Encode Remaining Length on a MQTT packet header, comprised of Variable
 * Header and Payload if present. It does not take into account the bytes
 * required to store itself. Refer to MQTT v3.1.1 algorithm for the
 * implementation.
 */
int mqtt_encode_length(unsigned char *buf, size_t len) {
    int bytes = 0;
    do {
        if (bytes + 1 > MAX_LEN_BYTES)
            return bytes;
        short d = len % 128;
        len /= 128;
        /* if there are more digits to encode, set the top bit of this digit */
        if (len > 0)
            d |= 128;
        buf[bytes++] = d;
    } while (len > 0);
    return bytes;
}

/*
 * Decode Remaining Length comprised of Variable Header and Payload if
 * present. It does not take into account the bytes for storing length. Refer
 * to MQTT v3.1.1 algorithm for the implementation suggestion.
 *
 * TODO Handle case where multiplier > 128 * 128 * 128
 */
unsigned long long mqtt_decode_length(const unsigned char **buf) {
    char c;
    int multiplier = 1;
    unsigned long long value = 0LL;
    do {
        c = **buf;
        value += (c & 127) * multiplier;
        multiplier *= 128;
        (*buf)++;
    } while ((c & 128) != 0);
    return value;
}

/*
 * MQTT unpacking functions
 */
static size_t unpack_mqtt_connect(const unsigned char *raw,
                                  union mqtt_header *hdr,
                                  union mqtt_packet *pkt) {

    struct mqtt_connect connect = { .header = *hdr };
    pkt->connect = connect;

    const unsigned char *init = raw;
    /*
     * Second byte of the fixed header, contains the length of remaining bytes
     * of the connect packet
     */
    size_t len = mqtt_decode_length(&raw);

    /*
     * For now we ignore checks on protocol name and reserved bits, just skip
     * to the 8th byte
     */
    raw = init + 8;

    /* Read variable header byte flags */
    pkt->connect.byte = unpack_u8((const uint8_t **) &raw);

    /* Read keepalive MSB and LSB (2 bytes word) */
    pkt->connect.payload.keepalive = unpack_u16((const uint8_t **) &raw);

    /* Read CID length (2 bytes word) */
    uint16_t cid_len = unpack_u16((const uint8_t **) &raw);

    /* Read the client id */
    if (cid_len > 0) {
        pkt->connect.payload.client_id = malloc(cid_len + 1);
        unpack_bytes((const uint8_t **) &raw, cid_len,
                     pkt->connect.payload.client_id);
    }

    /* Read the will topic and message if will is set on flags */
    if (pkt->connect.bits.will == 1) {

        uint16_t will_topic_len = unpack_u16((const uint8_t **) &raw);
        pkt->connect.payload.will_topic = malloc(will_topic_len + 1);
        unpack_bytes((const uint8_t **) &raw, will_topic_len,
                     pkt->connect.payload.will_topic);

        uint16_t will_message_len = unpack_u16((const uint8_t **) &raw);
        pkt->connect.payload.will_message = malloc(will_message_len + 1);
        unpack_bytes((const uint8_t **) &raw, will_message_len,
                     pkt->connect.payload.will_message);
    }

    /* Read the username if username flag is set */
    if (pkt->connect.bits.username == 1) {
        uint16_t username_len = unpack_u16((const uint8_t **) &raw);
        pkt->connect.payload.username = malloc(username_len + 1);
        unpack_bytes((const uint8_t **) &raw, username_len,
                     pkt->connect.payload.username);
    }

    /* Read the password if password flag is set */
    if (pkt->connect.bits.password == 1) {
        uint16_t password_len = unpack_u16((const uint8_t **) &raw);
        pkt->connect.payload.password = malloc(password_len + 1);
        unpack_bytes((const uint8_t **) &raw, password_len,
                     pkt->connect.payload.password);
    }

    return len;
}

static size_t unpack_mqtt_publish(const unsigned char *raw,
                                  union mqtt_header *hdr,
                                  union mqtt_packet *pkt) {
    struct mqtt_publish publish = { .header = *hdr };
    pkt->publish = publish;

    /*
     * Second byte of the fixed header, contains the length of remaining bytes
     * of the connect packet
     */
    size_t len = mqtt_decode_length(&raw);

    /* Read topic length and topic of the soon-to-be-published message */
    uint16_t topic_len = unpack_u16((const uint8_t **) &raw);
    pkt->publish.topiclen = topic_len;
    pkt->publish.topic = malloc(topic_len + 1);
    unpack_bytes((const uint8_t **) &raw, topic_len, pkt->publish.topic);

    uint16_t message_len = len;

    /* Read packet id */
    if (publish.header.bits.qos > AT_MOST_ONCE) {
        pkt->publish.pkt_id = unpack_u16((const uint8_t **) &raw);
        message_len -= sizeof(uint16_t);
    }

    /*
     * Message len is calculated subtracting the length of the variable header
     * from the Remaining Length field that is in the Fixed Header
     */
    message_len -= (sizeof(uint16_t) + topic_len);
    pkt->publish.payloadlen = message_len;
    pkt->publish.payload = malloc(message_len + 1);
    unpack_bytes((const uint8_t **) &raw, message_len, pkt->publish.payload);

    return len;
}

static size_t unpack_mqtt_subscribe(const unsigned char *raw,
                                    union mqtt_header *hdr,
                                    union mqtt_packet *pkt) {
    struct mqtt_subscribe subscribe = { .header = *hdr };

    /*
     * Second byte of the fixed header, contains the length of remaining bytes
     * of the connect packet
     */
    size_t len = mqtt_decode_length(&raw);
    size_t remaining_bytes = len;

    /* Read packet id */
    subscribe.pkt_id = unpack_u16((const uint8_t **) &raw);
    remaining_bytes -= sizeof(uint16_t);

    /*
     * Read in a loop all remaining bytes specified by len of the Fixed Header.
     * From now on the payload consists of 3-tuples formed by:
     *  - topic length
     *  - topic filter (string)
     *  - qos
     */
    int i = 0;
    while (remaining_bytes > 0) {

        /* Read length bytes of the first topic filter */
        uint16_t topic_len = unpack_u16((const uint8_t **) &raw);
        remaining_bytes -= sizeof(uint16_t);

        /* We have to make room for additional incoming tuples */
        subscribe.tuples = realloc(subscribe.tuples,
                                   (i+1) * sizeof(*subscribe.tuples));
        subscribe.tuples[i].topic_len = topic_len;
        subscribe.tuples[i].topic = malloc(topic_len + 1);
        unpack_bytes((const uint8_t **) &raw, topic_len,
                     subscribe.tuples[i].topic);
        remaining_bytes -= topic_len;
        subscribe.tuples[i].qos = unpack_u8((const uint8_t **) &raw);
        remaining_bytes -= sizeof(uint8_t);
        i++;
    }

    subscribe.tuples_len = i;
    pkt->subscribe = subscribe;

    return len;
}

static size_t unpack_mqtt_unsubscribe(const unsigned char *raw,
                                      union mqtt_header *hdr,
                                      union mqtt_packet *pkt) {
    struct mqtt_unsubscribe unsubscribe = { .header = *hdr };

    /*
     * Second byte of the fixed header, contains the length of remaining bytes
     * of the connect packet
     */
    size_t len = mqtt_decode_length(&raw);
    size_t remaining_bytes = len;

    /* Read packet id */
    unsubscribe.pkt_id = unpack_u16((const uint8_t **) &raw);
    remaining_bytes -= sizeof(uint16_t);

    /*
     * Read in a loop all remaining bytes specified by len of the Fixed Header.
     * From now on the payload consists of 2-tuples formed by:
     *  - topic length
     *  - topic filter (string)
     */
    int i = 0;
    while (remaining_bytes > 0) {

        /* Read length bytes of the first topic filter */
        uint16_t topic_len = unpack_u16((const uint8_t **) &raw);
        remaining_bytes -= sizeof(uint16_t);

        /* We have to make room for additional incoming tuples */
        unsubscribe.tuples = realloc(unsubscribe.tuples,
                                     (i+1) * sizeof(*unsubscribe.tuples));
        unsubscribe.tuples[i].topic_len = topic_len;
        unsubscribe.tuples[i].topic = malloc(topic_len + 1);
        unpack_bytes((const uint8_t **) &raw, topic_len,
                     unsubscribe.tuples[i].topic);
        remaining_bytes -= topic_len;

        i++;
    }

    unsubscribe.tuples_len = i;
    pkt->unsubscribe = unsubscribe;

    return len;
}

static size_t unpack_mqtt_ack(const unsigned char *raw,
                              union mqtt_header *hdr,
                              union mqtt_packet *pkt) {
    struct mqtt_ack ack = { .header = *hdr };

    /*
     * Second byte of the fixed header, contains the length of remaining bytes
     * of the connect packet
     */
    size_t len = mqtt_decode_length(&raw);

    ack.pkt_id = unpack_u16((const uint8_t **) &raw);
    pkt->ack = ack;

    return len;
}

typedef size_t mqtt_unpack_handler(const unsigned char *,
                                   union mqtt_header *,
                                   union mqtt_packet *);

/*
 * Unpack functions mapping unpacking_handlers positioned in the array based
 * on message type
 */
static mqtt_unpack_handler *unpack_handlers[11] = {
    NULL,
    unpack_mqtt_connect,
    NULL,
    unpack_mqtt_publish,
    unpack_mqtt_ack,
    unpack_mqtt_ack,
    unpack_mqtt_ack,
    unpack_mqtt_ack,
    unpack_mqtt_subscribe,
    NULL,
    unpack_mqtt_unsubscribe
};

int unpack_mqtt_packet(const unsigned char *raw, union mqtt_packet *pkt) {
    int rc = 0;

    /* Read first byte of the fixed header */
    unsigned char type = *raw;
    union mqtt_header header = {
        .byte = type
    };
    if (header.bits.type == DISCONNECT
        || header.bits.type == PINGREQ
        || header.bits.type == PINGRESP)
        pkt->header = header;
    else
        /* Call the appropriate unpack handler based on the message type */
        rc = unpack_handlers[header.bits.type](++raw, &header, pkt);

    return rc;
}