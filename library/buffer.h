//
// Created by eugene on 3/22/19.
//

#ifndef ZITI_SDK_BUFFER_H
#define ZITI_SDK_BUFFER_H

typedef struct buffer_s buffer;

buffer *new_buffer();
void free_buffer(buffer*);

void buffer_cleanup(buffer *);
int buffer_get_next(buffer*, uint32_t want, uint8_t** ptr);
void buffer_append(buffer*, uint8_t *buf, uint32_t len);
size_t buffer_available(buffer*);


#endif //ZITI_SDK_BUFFER_H
