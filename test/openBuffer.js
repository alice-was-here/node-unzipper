const test = require('tap').test;
const fs = require('fs');
const path = require('path');
const unzip = require('../');

test("get content of a single file entry out of a buffer", function (t) {
  const archive = path.join(__dirname, '../testData/compressed-standard/archive.zip');
  const buffer = fs.readFileSync(archive);

  return unzip.Open.buffer(buffer)
    .then(function(d) {
      const file = d.files.filter(function(file) {
        return file.path == 'file.txt';
      })[0];

      return file.buffer()
        .then(function(str) {
          const fileStr = fs.readFileSync(path.join(__dirname, '../testData/compressed-standard/inflated/file.txt'), 'utf8');
          t.equal(str.toString(), fileStr);
          t.end();
        });
    });
});