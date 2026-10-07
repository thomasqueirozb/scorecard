// Copyright 2021 OpenSSF Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package checks

import (
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"go.uber.org/mock/gomock"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/clients"
	mockrepo "github.com/ossf/scorecard/v5/clients/mockclients"
	"github.com/ossf/scorecard/v5/config"
	scut "github.com/ossf/scorecard/v5/utests"
)

func TestGithubTokenPermissions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		filenames []string
		expected  scut.TestReturn
	}{
		{
			name:      "run workflow codeql write test",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-run-codeql-write.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  2,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "run workflow no codeql write test",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-run-no-codeql-write.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  1,
				NumberOfInfo:  1,
				NumberOfDebug: 4,
			},
		},
		{
			name:      "run workflow write test",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-run-writes-2.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  3,
				NumberOfInfo:  2,
				NumberOfDebug: 4,
			},
		},
		{
			name:      "run package workflow write test",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-run-package-workflow-write.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  2,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "run package write test",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-run-package-write.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  1,
				NumberOfInfo:  1,
				NumberOfDebug: 4,
			},
		},
		{
			name:      "run writes test",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-run-writes.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  2,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "write all test",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-writeall.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MinResultScore,
				NumberOfWarn:  1,
				NumberOfInfo:  0,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "read all test",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-readall.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  2,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "no permission test",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-absent.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MinResultScore,
				NumberOfWarn:  1,
				NumberOfInfo:  1,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "writes test",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-writes.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  2,
				NumberOfDebug: 6,
			},
		},
		{
			name:      "reads test",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-reads.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  11,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "nones test",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-nones.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  11,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "none test",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-none.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  2,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "status/checks write",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-status-checks.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore - 1,
				NumberOfWarn:  2,
				NumberOfInfo:  3,
				NumberOfDebug: 6,
			},
		},
		{
			name:      "sec-events/deployments write",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-secevent-deployments.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore - 2,
				NumberOfWarn:  2,
				NumberOfInfo:  4,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "contents write",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-contents.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MinResultScore,
				NumberOfWarn:  1,
				NumberOfInfo:  3,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "actions write",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-actions.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MinResultScore,
				NumberOfWarn:  1,
				NumberOfInfo:  3,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "packages write",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-packages.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MinResultScore,
				NumberOfWarn:  1,
				NumberOfInfo:  2,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "Non-yaml file",
			filenames: []string{"./testdata/script.sh"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.InconclusiveResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  0,
				NumberOfDebug: 0,
			},
		},
		{
			name:      "package workflow contents write",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-contents-writes-no-release.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  1,
				NumberOfInfo:  1,
				NumberOfDebug: 4,
			},
		},
		{
			name:      "release workflow contents write",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-contents-writes-release.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  2,
				NumberOfDebug: 4,
			},
		},
		{
			name:      "release workflow contents write",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-contents-writes-release-mvn-release.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  2,
				NumberOfDebug: 4,
			},
		},
		{
			name:      "release workflow contents write semantic-release with npx",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-contents-writes-release-semantic-release.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  2,
				NumberOfDebug: 4,
			},
		},
		{
			name:      "release workflow contents write semantic-release with yarn command",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-contents-writes-release-semantic-release-yarn.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  2,
				NumberOfDebug: 4,
			},
		},
		{
			name:      "release workflow contents write semantic-release with pnpm and dlx",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-contents-writes-release-semantic-release-pnpm.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  2,
				NumberOfDebug: 4,
			},
		},
		{
			name:      "package workflow write",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-packages-writes.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  2,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "penalize job-level read without top level permissions",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-jobs-only.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore - 1,
				NumberOfWarn:  1,
				NumberOfInfo:  4,
				NumberOfDebug: 4,
			},
		},
		{
			name:      "security-events write, codeql comment",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-run-write-codeql-comment.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  1,
				NumberOfInfo:  1,
				NumberOfDebug: 4,
			},
		},
		{
			name:      "security-events write, known actions",
			filenames: []string{"./testdata/.github/workflows/github-workflow-permissions-secevent-known-actions.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  2, // This is constant.
				NumberOfDebug: 9, // This is 4 + (number of actions)
			},
		},
		{
			name: "two files mix run-level and top-level",
			filenames: []string{
				"./testdata/.github/workflows/github-workflow-permissions-top-level-only.yaml",
				"./testdata/.github/workflows/github-workflow-permissions-run-level-only.yaml",
			},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore - 1,
				NumberOfWarn:  1,
				NumberOfInfo:  3,
				NumberOfDebug: 9,
			},
		},
		{
			name: "two files mix run-level and absent",
			filenames: []string{
				"./testdata/.github/workflows/github-workflow-permissions-run-level-only.yaml",
				"./testdata/.github/workflows/github-workflow-permissions-absent.yaml",
			},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MinResultScore,
				NumberOfWarn:  2,
				NumberOfInfo:  2,
				NumberOfDebug: 9,
			},
		},
		{
			name: "two files mix top-level and absent",
			filenames: []string{
				"./testdata/.github/workflows/github-workflow-permissions-top-level-only.yaml",
				"./testdata/.github/workflows/github-workflow-permissions-absent.yaml",
			},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MinResultScore,
				NumberOfWarn:  1,
				NumberOfInfo:  2,
				NumberOfDebug: 10,
			},
		},
		{
			name: "read permission with GitHub pages write",
			filenames: []string{
				"./testdata/.github/workflows/github-workflow-permissions-gh-pages.yaml",
			},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  2,
				NumberOfDebug: 5,
			},
		},
		{
			name: "don't penalize job-level writes",
			filenames: []string{
				"./testdata/.github/workflows/github-workflow-permissions-run-multiple-writes.yaml",
			},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  7, // number of job-level write permissions
				NumberOfInfo:  1, // read-only top-level permissions
				NumberOfDebug: 4, // This is 4 + (number of actions = 0)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockRepo := mockrepo.NewMockRepoClient(ctrl)
			mockRepo.EXPECT().GetDefaultBranchName().Return("main", nil).AnyTimes()

			main := "main"
			mockRepo.EXPECT().URI().Return("github.com/ossf/scorecard").AnyTimes()
			mockRepo.EXPECT().GetDefaultBranch().Return(&clients.BranchRef{Name: &main}, nil).AnyTimes()
			mockRepo.EXPECT().ListFiles(gomock.Any()).DoAndReturn(func(predicate func(string) (bool, error)) ([]string, error) {
				files := []string{}
				for _, fn := range tt.filenames {
					files = append(files, strings.TrimPrefix(fn, "./testdata/"))
				}
				return files, nil
			}).AnyTimes()
			mockRepo.EXPECT().GetFileReader(gomock.Any()).DoAndReturn(func(fn string) (io.ReadCloser, error) {
				return os.Open("./testdata/" + fn)
			}).AnyTimes()
			dl := scut.TestDetailLogger{}
			c := checker.CheckRequest{
				RepoClient: mockRepo,
				Dlogger:    &dl,
			}

			res := TokenPermissions(&c)

			scut.ValidateTestReturn(t, tt.name, &tt.expected, &res, &dl)
		})
	}
}

func TestGithubTokenPermissionsAllowedWrites(t *testing.T) {
	t.Parallel()
	allowedWrites := []config.AllowedWrite{
		{Permission: "packages", Uses: "actions/delete-package-versions", Reason: "deletes old images"},
		{Permission: "contents", Uses: "octo-org/workflows/.github/workflows/publish.yml", Reason: "creates releases"},
	}
	tests := []struct {
		name          string
		filename      string
		allowedWrites []config.AllowedWrite
		wantScore     int
		wantWarnLines []uint
	}{
		{
			// The caller's 'contents: write' (line 29) is declared by the called local
			// workflow, so it is accepted without configuration. Its 'packages: write'
			// (line 30) is not declared by the called workflow and warns. A missing
			// local workflow (line 35) and a remote one (line 40) are not accepted.
			name:          "without configuration, only writes declared by called local workflows are accepted",
			filename:      "./testdata/.github/workflows/github-workflow-permissions-allowed-writes.yaml",
			wantScore:     checker.MaxResultScore,
			wantWarnLines: []uint{23, 30, 35, 40, 46, 53, 60},
		},
		{
			// Only the jobs that use a configured action or reusable workflow, and only
			// the configured permissions, are accepted. Other jobs in the file still warn.
			name:          "configured writes are accepted per job and permission",
			filename:      "./testdata/.github/workflows/github-workflow-permissions-allowed-writes.yaml",
			allowedWrites: allowedWrites,
			wantScore:     checker.MaxResultScore,
			wantWarnLines: []uint{30, 35, 46, 53, 60},
		},
		{
			// Job rules apply to one job of one workflow file, for one permission.
			name:     "job rules are accepted for the job, workflow file and permission",
			filename: "./testdata/.github/workflows/github-workflow-permissions-allowed-writes.yaml",
			allowedWrites: []config.AllowedWrite{
				{
					Permission: "contents",
					Workflow:   ".github/workflows/github-workflow-permissions-allowed-writes.yaml",
					Job:        "call-missing-local-workflow",
					Reason:     "accepted: line 35",
				},
				{
					Permission: "packages",
					Workflow:   ".github/workflows/github-workflow-permissions-allowed-writes.yaml",
					Job:        "other-packages",
					Reason:     "accepted: line 46",
				},
				{
					Permission: "packages",
					Workflow:   ".github/workflows/other-workflow.yaml",
					Job:        "similar-action",
					Reason:     "other workflow file: line 60 still warns",
				},
				{
					Permission: "statuses",
					Workflow:   ".github/workflows/github-workflow-permissions-allowed-writes.yaml",
					Job:        "similar-action",
					Reason:     "other permission: line 60 still warns",
				},
			},
			wantScore:     checker.MaxResultScore,
			wantWarnLines: []uint{23, 30, 40, 53, 60},
		},
		{
			name:          "top-level writes are never accepted",
			filename:      "./testdata/.github/workflows/github-workflow-permissions-allowed-writes-top-level.yaml",
			allowedWrites: allowedWrites,
			wantScore:     checker.MinResultScore,
			wantWarnLines: []uint{17},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockRepo := mockrepo.NewMockRepoClient(ctrl)
			mockRepo.EXPECT().URI().Return("github.com/ossf/scorecard").AnyTimes()
			mockRepo.EXPECT().GetDefaultBranchName().Return("main", nil).AnyTimes()
			mockRepo.EXPECT().ListFiles(gomock.Any()).Return(
				[]string{strings.TrimPrefix(tt.filename, "./testdata/")}, nil).AnyTimes()
			mockRepo.EXPECT().GetFileReader(gomock.Any()).DoAndReturn(func(fn string) (io.ReadCloser, error) {
				return os.Open("./testdata/" + fn)
			}).AnyTimes()
			dl := scut.TestDetailLogger{}
			c := checker.CheckRequest{
				RepoClient: mockRepo,
				Dlogger:    &dl,
				Config: config.Config{
					TokenPermissions: config.TokenPermissions{AllowedWrites: tt.allowedWrites},
				},
			}

			res := TokenPermissions(&c)
			if res.Error != nil {
				t.Fatalf("unexpected error: %v", res.Error)
			}
			if res.Score != tt.wantScore {
				t.Errorf("score: got %d, want %d", res.Score, tt.wantScore)
			}
			var gotWarnLines []uint
			for _, d := range dl.Flush() {
				if d.Type != checker.DetailWarn {
					continue
				}
				f := d.Msg.Finding
				if f == nil || f.Location == nil || f.Location.LineStart == nil {
					t.Fatalf("warning without a line: %+v", d.Msg)
				}
				gotWarnLines = append(gotWarnLines, *f.Location.LineStart)
			}
			slices.Sort(gotWarnLines)
			if !slices.Equal(gotWarnLines, tt.wantWarnLines) {
				t.Errorf("warning lines: got %v, want %v", gotWarnLines, tt.wantWarnLines)
			}
		})
	}
}

func TestGithubTokenPermissionsLineNumber(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		filename string
		expected []struct {
			lineNumber uint
		}
	}{
		{
			name:     "Job level write permission",
			filename: "./testdata/.github/workflows/github-workflow-permissions-run-no-codeql-write.yaml",
			expected: []struct {
				lineNumber uint
			}{
				{
					lineNumber: 22,
				},
			},
		},
		{
			name:     "Workflow level write permission",
			filename: "./testdata/.github/workflows/github-workflow-permissions-writeall.yaml",
			expected: []struct {
				lineNumber uint
			}{
				{
					lineNumber: 16,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := strings.Replace(tt.filename, "./testdata/", "", 1)
			ctrl := gomock.NewController(t)
			mockRepo := mockrepo.NewMockRepoClient(ctrl)

			main := "main"
			mockRepo.EXPECT().URI().Return("github.com/ossf/scorecard").AnyTimes()
			mockRepo.EXPECT().GetDefaultBranchName().Return(main, nil).AnyTimes()
			mockRepo.EXPECT().ListFiles(gomock.Any()).DoAndReturn(func(predicate func(string) (bool, error)) ([]string, error) {
				return []string{p}, nil
			}).AnyTimes()
			mockRepo.EXPECT().GetFileReader(gomock.Any()).DoAndReturn(func(fn string) (io.ReadCloser, error) {
				return os.Open(tt.filename)
			}).AnyTimes()
			dl := scut.TestDetailLogger{}
			c := checker.CheckRequest{
				RepoClient: mockRepo,
				Dlogger:    &dl,
			}

			_ = TokenPermissions(&c)

			for _, expectedLog := range tt.expected {
				isExpectedLog := func(logMessage checker.LogMessage, logType checker.DetailType) bool {
					return logMessage.Finding != nil &&
						logMessage.Finding.Location != nil &&
						logMessage.Finding.Location.LineStart != nil &&
						*logMessage.Finding.Location.LineStart == expectedLog.lineNumber &&
						logMessage.Finding.Location.Path == p &&
						logType == checker.DetailWarn
				}
				if !scut.ValidateLogMessage(isExpectedLog, &dl) {
					t.Errorf("test failed: log message not present: %+v", tt.expected)
				}
			}
		})
	}
}
