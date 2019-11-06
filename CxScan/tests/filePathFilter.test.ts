import * as assert from 'assert';
import {FilePathFilter} from "../services/filePathFilter";

describe('FilePathFilter', function () {
    it('should include all paths if the filter string is empty', function() {
        const target = new FilePathFilter('');
        const paths = [
            'basePage.java',
            '.classpath',
            'noextension'
        ];
        paths.forEach(path => {
            assert.ok(target.includes(path), `'${path}' should be included.`);
        });
    });
});