/**
 * @author Karl Moad <github.com/karlmoad>
 */

var gulp = require('gulp');
var uglify = require('gulp-uglify');
var jsdoc = require('gulp-jsdoc3');
var pump = require('pump');

gulp.task('compress', function (cb) {
    pump([
            gulp.src('lib/*.js'),
            uglify(),
            gulp.dest('dist')
        ],
        cb
    );
});

gulp.task('document', function (cb) {
    var config = require('./jsdoc.json');
    gulp.src(['README.md', './lib/*.js'], {read: false})
        .pipe(jsdoc(config,cb));
});


gulp.task('default',['document','compress']);