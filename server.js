/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2019, Gary Guo
 */
const http = require('http');
const { hash } = require('./db');

/**
 * Create a HTTP RESTful API server for a database.
 * 
 * @param {*} db BlobDatabase to serve
 * @returns {http.Server}
 */
function createServer(db) {
  const requestHandler = (request, response) => {
    try {
      let parsedUrl = new URL(request.url, 'http://localhost/');

      let blobName = parsedUrl.pathname;
      if (!blobName.startsWith('/blobs/')) {
        throw new RangeError('Illegal request URL. Must begin with /blobs/');
      }
      blobName = blobName.slice('/blobs/'.length);

      let blobHash = blobName.length == 0 ? null : Buffer.from(blobName, 'hex');
      if (blobHash && blobHash.length !== 32) {
        throw new RangeError('Illegal request URL. Hash is not valid');
      }

      let link = parsedUrl.searchParams.get('link');
      let linkHash = link == null ? null : Buffer.from(link, 'hex');
      if (linkHash && linkHash.length !== 32) {
        throw new RangeError('Illegal request URL. Hash is not valid');
      }

      switch (request.method) {
        case 'GET': {
          if (blobHash == null) throw new RangeError('Hash must be specified for GET');
          db.get(blobHash).then(buffer => {
            if (!buffer) {
              response.statusCode = 404;
              response.end();
              return;
            } else {
              response.setHeader('Content-Type', 'text/plain; charset=utf-8');
              response.end(buffer);
            }
          });
          break;
        }
        case 'PUT': {
          let buffers = [];
          request.on('data', chunk => {
            buffers.push(chunk);
          });
          request.on('end', () => {
            // No no-op if the request is terminated
            if (!request.complete) return;
            let concat = Buffer.concat(buffers);
            // If hash is supplied, check it.
            if (blobHash) {
              if (hash(concat).compare(blobHash) != 0) {
                response.statusCode = 400;
                response.end('Hash mismatch with body');
                return;
              }
            }
            let promise = linkHash ? db.insertLink(linkHash, concat) : db.insert(concat);
            promise.then(newHash => {
              response.statusCode = 201;
              response.setHeader('Location', '/blobs/' + newHash);
              response.end();
            }, ex => {
              console.log(ex);
              response.statusCode = 500;
              response.end(ex.message);
            });
          });
          break;
        }
        case 'PATCH': {
          if (blobHash == null || linkHash == null) throw new RangeError('Hash must be specified for PATCH');
          db.link(linkHash, blobHash).then(() => {
            response.statusCode = 204;
            response.end();
          }, ex => {
            console.log(ex);
            response.statusCode = 500;
            response.end(ex.message);
          });
          break;
        }
        default: throw new RangeError('Unexpected requeset method');
      }
    } catch (ex) {
      if (ex instanceof RangeError) {
        response.statusCode = 400;
      } else {
        response.statusCode = 500;
        console.log(ex);
      }
      response.end(ex.message);
    }
  }
  return http.createServer(requestHandler);
}
exports.createServer = createServer;
