import * as assert from 'assert';
import {FilePathFilter} from "../services/filePathFilter";

describe('FilePathFilter', function () {
    type FilterTestCase = [string, boolean];

    it('should include all files if the filter string is empty', function () {
        verifyInclusion('', [
            ['basePage.java', true],
            ['.classpath', true],
            ['noextension', true],
        ]);
    });

    it('should support including only files of certain types', function () {
        verifyInclusion('*.java,*.js', [
            ['basePage.java', true],
            ['myscript.js', true],
            ['myimage.png', false],
            ['noext', false],
        ]);
    });

    it('should support including all files except specified ones', function () {
        verifyInclusion('!*.png,!*.class', [
            ['myimage.png', false],
            ['basePage.class', false],
            ['basePage.java', true],
            ['myscript.js', true],
            ['noext', true],
            ['.classpath', true],
        ]);
    });

    it('should ignore leading and trailing whitespace in patterns', function () {
        verifyInclusion('   *.java  ,      *.js ', [
            ['basePage.java', true],
            ['myscript.js', true],
            ['myimage.png', false],
            ['noext', false],
        ]);
    });

    it('should ignore empty patterns', function () {
        verifyInclusion('*.java,  ,, , *.js', [
            ['basePage.java', true],
            ['myscript.js', true],
            ['myimage.png', false],
            ['noext', false],
        ]);
    });

    function verifyInclusion(filterString: string, testCases: FilterTestCase[]) {
        const filter = new FilePathFilter(filterString);

        testCases.forEach(pathTestCase => {
            const path = pathTestCase[0];
            const shouldBeIncluded = pathTestCase[1];

            const assertion = shouldBeIncluded ? 'included' : 'excluded';
            assert.equal(filter.includes(path), shouldBeIncluded, `'${path}' should be ${assertion} by the filter string: '${filterString}'`);
        });
    }
});