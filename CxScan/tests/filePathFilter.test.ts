import {FilePathFilter} from "../services/filePathFilter";
import {FilterTestCases, Utils} from "./utils";

describe('FilePathFilter', function () {

    describe('filterPattern parameter', function () {
        it('should include all files if the filter pattern is empty', function () {
            Utils.verifyFilterPattern('', [
                ['basePage.java', true],
                ['.classpath', true],
                ['noextension', true],
                ['parent/subdir/file.txt', true],
                ['parent/subdir/.npmrc', true],
                ['parent/subdir/noextension', true],
            ]);
        });

        it('should support including only files of certain types on all directory levels', function () {
            Utils.verifyFilterPattern('**/*.java,**/*.js', [
                ['basePage.java', true],
                ['myscript.js', true],
                ['.classpath', false],
                ['noextension', false],
                ['myimage.png', false],
                ['parent/subdir/basePage.java', true],
                ['parent/subdir/myscript.js', true],
                ['parent/subdir/.npmrc', false],
                ['parent/subdir/file.txt', false],
                ['parent/subdir/noextension', false],
            ]);
        });

        it('should support including all files except specified ones on all directory levels', function () {
            Utils.verifyFilterPattern('!**/*.png,!**/*.class', [
                ['basePage.java', true],
                ['.classpath', true],
                ['noextension', true],
                ['myimage.png', false],
                ['parent/subdir/basePage.java', true],
                ['parent/subdir/.npmrc', true],
                ['parent/subdir/basePage.class', false],
                ['parent/subdir/noextension', true],
            ]);
        });

        it('should be case-sensitive', function () {
            Utils.verifyFilterPattern('**/*.test.cs', [
                ['parent/subdir/first.test.cs', true],
                ['parent/subdir/second.Test.cs', false]
            ]);
        });

        it('should allow to include a certain directory, except for specific files in a subdirectory', function () {
            Utils.verifyFilterPattern('parent/**,!parent/subdir/*.aspx', [
                ['parent/test.java', true],
                ['parent/subdir/test.java', true],
                ['parent/subdir/dir1/dir2/test.java', true],

                ['parent/subdir/page.aspx', false],
                ['parent/subdir/dir1/page.aspx', true],
                ['root.txt', false],
                ['another/test.java', false]
            ]);
        });

        describe('path separator handling', function () {
            it('should treat forward slash as a separator', function () {
                Utils.verifyFilterPattern('parent/subdir/dir3/get*', [
                    ['parent/subdir/dir3/getMessage.cs', true]
                ]);
            });

            it('should not treat backslash as a separator', function () {
                Utils.verifyFilterPattern('parent\\subdir\\dir3\\get*', [
                    ['parent/subdir/dir3/getMessage.cs', false]
                ]);
            });

            it('should support globstars (**)', function () {
                Utils.verifyFilterPattern('**/test/**/get*', [
                    ['parent/subdir/test/getMessage.cs', true],
                    ['parent/subdir/test/dir1/dir2/getMessage.cs', true]
                ]);
            });
        });

        describe('ignoring certain characters in patterns', function () {
            const testCases: FilterTestCases = [
                ['parent/subdir/basePage.java', true],
                ['parent/subdir/myscript.js', true],
                ['parent/subdir/myimage.png', false],
                ['parent/subdir/noext', false],
                ['parent/subdir/.npmrc', false],
            ];

            it('should ignore leading and trailing whitespace', function () {
                Utils.verifyFilterPattern('   **/*.java  ,      **/*.js ', testCases);
            });

            it('should ignore empty patterns', function () {
                Utils.verifyFilterPattern('**/*.java,  ,, , **/*.js', testCases);
            });

            it('should ignore newlines between patterns', function () {
                Utils.verifyFilterPattern('\n**/*.java,\n**/*.js\n', testCases);
                Utils.verifyFilterPattern('\r\n**/*.java,\r\n**/*.js\r\n', testCases);
            });
        });
    });

    describe('excludedFolders parameter', function () {
        it('should exclude folders at any level', function () {
            Utils.verifyExcludedFolders('bin,.svn', [
                ['test.java', true],
                ['bin/test.exe', false],
                ['.svn/test.java', false],
                ['parent/subdir/bin/test.exe', false],
                ['parent/subdir/.svn/info', false]
            ]);
        });

        it('should be treated as complete folder names', function () {
            Utils.verifyExcludedFolders('bin', [
                ['parent/subdir/binder/test.java', true],
                ['parent/subdir/trashbin/test.java', true],
                ['parent/subdir/bin/test.java', false],
            ]);
        });
    })
});


