#include <unistd.h>

#include "persist.h"

using namespace std;

/// Atomically add an incremental update message to the open file
///
/// This variant puts a delimiter, a string, two vectors, and a zero into the
/// file.
///
/// @param logfile The file to write into
/// @param delim   The 8-byte string that starts the log entry
/// @param s       The string to add to the message
/// @param v1      The first vector to add to the message
/// @param v2      The second vector to add to the message
void log_svv0(FILE *logfile, const string &delim, const string &s,
              const vector<uint8_t> &v1, const vector<uint8_t> &v2) {
  vector<uint8_t> buffer(delim.begin(), delim.end());
  // sizes
  size_t slen = s.size();
  buffer.insert(buffer.end(), (char *)&slen, ((char *)&slen) + sizeof(slen));
  size_t v1len = v1.size();
  buffer.insert(buffer.end(), (char *)&v1len, ((char *)&v1len) + sizeof(v1len));
  size_t v2len = v2.size();
  buffer.insert(buffer.end(), (char *)&v2len, ((char *)&v2len) + sizeof(v2len));
  size_t zero = 0;
  buffer.insert(buffer.end(), (char *)&zero, ((char *)&zero) + sizeof(zero));
  // content
  buffer.insert(buffer.end(), s.begin(), s.end());
  buffer.insert(buffer.end(), v1.begin(), v1.end());
  buffer.insert(buffer.end(), v2.begin(), v2.end());
  // padding
  size_t num = 8 - (slen + v1len + zero) % 8;
  if (num != 8)
    buffer.insert(buffer.end(), (char *)&zero, ((char *)&zero) + num);

  fwrite(buffer.data(), sizeof(char), buffer.size(), logfile);
  fflush(logfile);
  fsync(fileno(logfile));
}

/// Atomically add an incremental update message to the open file
///
/// This variant puts a delimiter, a string, and a vector into the file.
///
/// @param logfile The file to write into
/// @param delim   The 8-byte string that starts the log entry
/// @param s1      The string to add to the message
/// @param v1      The vector to add to the message
void log_sv(FILE *logfile, const string &delim, const string &s1,
            const vector<uint8_t> &v1) {
  vector<uint8_t> buffer(delim.begin(), delim.end());
  // sizes
  size_t slen = s1.size();
  buffer.insert(buffer.end(), (char *)&slen, ((char *)&slen) + sizeof(slen));
  size_t vlen = v1.size();
  buffer.insert(buffer.end(), (char *)&vlen, ((char *)&vlen) + sizeof(vlen));
  // content
  buffer.insert(buffer.end(), s1.begin(), s1.end());
  buffer.insert(buffer.end(), v1.begin(), v1.end());
  // padding
  size_t zero = 0, num = 8 - (slen + vlen) % 8;
  if (num != 8)
    buffer.insert(buffer.end(), (char *)&zero, ((char *)&zero) + num);

  fwrite(buffer.data(), sizeof(char), buffer.size(), logfile);
  fflush(logfile);
  fsync(fileno(logfile));
}

/// Atomically add an incremental update message to the open file
///
/// This variant puts a delimiter and a string into the file
///
/// @param logfile The file to write into
/// @param delim   The 8-byte string that starts the log entry
/// @param s1      The string to add to the message
void log_s(FILE *logfile, const string &delim, const string &s1) {
  vector<uint8_t> buffer(delim.begin(), delim.end());
  // size
  size_t slen = s1.size();
  buffer.insert(buffer.end(), (char *)&slen, ((char *)&slen) + sizeof(slen));
  // content
  buffer.insert(buffer.end(), s1.begin(), s1.end());
  // padding
  size_t zero = 0, num = 8 - (slen) % 8;
  if (num != 8)
    buffer.insert(buffer.end(), (char *)&zero, ((char *)&zero) + num);

  fwrite(buffer.data(), sizeof(char), buffer.size(), logfile);
  fflush(logfile);
  fsync(fileno(logfile));
}
