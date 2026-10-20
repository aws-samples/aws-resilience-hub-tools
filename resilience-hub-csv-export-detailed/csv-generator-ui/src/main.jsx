// RAP Assessment Report page, built with Cloudscape (https://cloudscape.design).
// csv-generator-nextgen.py writes the report data into <script id="rap-data">; this page only displays it.
import React, { useEffect, useState } from 'react';
import { flushSync } from 'react-dom';
import { createRoot } from 'react-dom/client';
import '@cloudscape-design/global-styles/index-base.css';
import './print.css';
import { applyMode, Mode } from '@cloudscape-design/global-styles';
import { colorBackgroundLayoutMain, colorBorderStatusInfo } from '@cloudscape-design/design-tokens';
import { useCollection } from '@cloudscape-design/collection-hooks';
import { I18nProvider } from '@cloudscape-design/components/i18n';
import messages from '@cloudscape-design/components/i18n/messages/all.en';
import AppLayout from '@cloudscape-design/components/app-layout';
import Badge from '@cloudscape-design/components/badge';
import Box from '@cloudscape-design/components/box';
import BreadcrumbGroup from '@cloudscape-design/components/breadcrumb-group';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Flashbar from '@cloudscape-design/components/flashbar';
import Header from '@cloudscape-design/components/header';
import HelpPanel from '@cloudscape-design/components/help-panel';
import KeyValuePairs from '@cloudscape-design/components/key-value-pairs';
import Link from '@cloudscape-design/components/link';
import Pagination from '@cloudscape-design/components/pagination';
import SideNavigation from '@cloudscape-design/components/side-navigation';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextContent from '@cloudscape-design/components/text-content';
import TopNavigation from '@cloudscape-design/components/top-navigation';

const data = JSON.parse(document.getElementById('rap-data').textContent);
const TITLE = 'RAP Assessment Report';
const SEVERITIES = ['HIGH', 'MEDIUM', 'LOW'];
const BADGE = { HIGH: 'severity-high', MEDIUM: 'severity-medium', LOW: 'severity-low' };
const PAGE_SIZE = 20;
// Actual values that only repeat the result
const REPEATS_RESULT = ['met', 'not met', 'not evaluated'];
const M1_ROW = 'M1 Assessment requirements';

const serviceHref = service => `#/services/${service.id}`;
const gapCount = service => service.m1Gaps.length + service.m2Gaps.length;
const plural = (count, word) => `${count} ${word}${count === 1 ? '' : 's'}`;
const joinAnd = items => (items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`);

function Verdict({ ready }) {
  return <StatusIndicator type={ready ? 'success' : 'error'}>{ready ? 'READY' : 'NOT READY'}</StatusIndicator>;
}

function Result({ met, actual }) {
  const value = REPEATS_RESULT.includes(actual) ? '' : ` · ${actual}`;
  if (met === null) {
    return <StatusIndicator type="stopped">Not evaluated{value}</StatusIndicator>;
  }
  return <StatusIndicator type={met ? 'success' : 'error'}>{(met ? 'Met' : 'Not met') + value}</StatusIndicator>;
}

function PlainList({ items }) {
  return (
    <ul style={{ margin: 0, paddingInlineStart: 20 }}>
      {items.map((item, index) => (
        <li key={index}>{item}</li>
      ))}
    </ul>
  );
}

function BulletList({ items }) {
  return (
    <TextContent>
      <PlainList items={items} />
    </TextContent>
  );
}

function Stat({ label, value, total, hint }) {
  return (
    <div>
      <Box variant="awsui-key-label">{label}</Box>
      <Box variant="awsui-value-large">
        {value}
        {total !== undefined && (
          <Box variant="span" fontSize="heading-l" fontWeight="normal" color="text-body-secondary">
            {' '}/ {total}
          </Box>
        )}
      </Box>
      {hint && <Box color="text-body-secondary">{hint}</Box>}
    </div>
  );
}

function VerdictStat({ label, ready, hint }) {
  return (
    <div>
      <Box variant="awsui-key-label">{label}</Box>
      <Box variant="awsui-value-large" color={ready ? 'text-status-success' : 'text-status-error'}>
        <span style={{ overflowWrap: 'normal', wordBreak: 'normal' }}>{ready ? 'READY' : 'NOT READY'}</span>
      </Box>
      <Box color="text-body-secondary">{hint}</Box>
    </div>
  );
}

function Item({ title, children }) {
  return (
    <div>
      <Box fontWeight="bold">{title}</Box>
      {children}
    </div>
  );
}

function Callout({ title, children }) {
  return (
    <Container
      header={<Header variant="h2">{title}</Header>}
      style={{ root: { background: colorBackgroundLayoutMain, borderColor: colorBorderStatusInfo, borderWidth: '0 0 0 4px' } }}
    >
      {children}
    </Container>
  );
}

function InfoLink({ onFollow }) {
  return (
    <Link variant="info" onFollow={onFollow}>
      Info
    </Link>
  );
}

function overviewNotices() {
  const notices = [];
  if (data.errors.length) {
    notices.push({
      id: 'errors',
      type: 'error',
      header: 'Some Regions or services were skipped, so the report is incomplete',
      content: <PlainList items={data.errors} />,
    });
  }
  if (data.warnings.length) {
    notices.push({ id: 'warnings', type: 'warning', header: 'Warnings', content: <PlainList items={data.warnings} /> });
  }
  if (data.classicOnly.length) {
    notices.push({
      id: 'classic',
      type: 'info',
      header: `Next generation Resilience Hub is not available yet in ${data.classicOnly.join(', ')}`,
      content: 'Use csv-generator.py (AWS Resilience Hub classic) for applications in these Regions.',
    });
  }
  if (!data.services.length) {
    notices.push({
      id: 'none',
      type: 'info',
      header: 'No next generation Resilience Hub services found',
      content: 'For AWS Resilience Hub (classic) applications, use csv-generator.py.',
    });
  }
  return notices;
}

function ServicesTable() {
  const { items, collectionProps } = useCollection(data.services, { sorting: {} });
  return (
    <Table
      {...collectionProps}
      variant="container"
      items={items}
      trackBy="id"
      header={
        <Header
          counter={`(${data.services.length})`}
          description="Score is the RAP-derived resiliency score. Choose a service to see each requirement, the score and the findings to address."
        >
          Services
        </Header>
      }
      columnDefinitions={[
        {
          id: 'name',
          header: 'Service',
          cell: s => (
            <div>
              <Link href={serviceHref(s)}>{s.name}</Link>
              <Box color="text-body-secondary" fontSize="body-s">
                {s.region}
              </Box>
            </div>
          ),
          sortingField: 'name',
          isRowHeader: true,
        },
        { id: 'm1', header: 'M1 Assessment', cell: s => <Verdict ready={s.m1Ready} />, sortingField: 'm1Ready' },
        { id: 'm2', header: 'M2 Remediation', cell: s => <Verdict ready={s.m2Ready} />, sortingField: 'm2Ready' },
        { id: 'score', header: 'Score', cell: s => (s.assessed ? s.score : '-'), sortingField: 'score' },
        { id: 'gaps', header: 'Requirements not met', cell: gapCount, sortingComparator: (a, b) => gapCount(a) - gapCount(b) },
        { id: 'assessed', header: 'Last assessed', cell: s => s.lastAssessed.slice(0, 10) || 'Not assessed', sortingField: 'lastAssessed' },
      ]}
    />
  );
}

function PhaseNames({ phase, ready }) {
  const yes = data.services.filter(s => s[ready]).map(s => s.name);
  const no = data.services.filter(s => !s[ready]).map(s => s.name);
  return (
    <Item title={phase}>
      {yes.length > 0 && (
        <div>
          <StatusIndicator type="success">READY: {yes.join(', ')}</StatusIndicator>
        </div>
      )}
      {no.length > 0 && (
        <div>
          <StatusIndicator type="error">NOT READY: {no.join(', ')}</StatusIndicator>
        </div>
      )}
    </Item>
  );
}

function ScoreParts({ parts }) {
  return (
    <SpaceBetween size="m">
      {parts.map(([value, label, hint]) => (
        <Item key={label} title={`${value} · ${label}`}>
          <Box variant="small" color="text-body-secondary">
            {hint}
          </Box>
        </Item>
      ))}
    </SpaceBetween>
  );
}

function Overview({ openHelp }) {
  const total = data.services.length;
  const m1 = data.services.filter(s => s.m1Ready).length;
  const m2 = data.services.filter(s => s.m2Ready).length;
  const regions = [...new Set(data.services.map(s => s.region))];
  const open = data.services.flatMap(s => s.toAddress);
  const description = [
    'Next generation AWS Resilience Hub',
    regions.length ? `${plural(total, 'service')} in ${regions.join(', ')}` : 'no services',
    `generated ${data.generated}`,
  ].join(' · ');
  return (
    <ContentLayout
      header={
        <Header variant="h1" info={<InfoLink onFollow={openHelp} />} description={description}>
          Account {data.account}
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Container>
          <SpaceBetween size="l">
            <ColumnLayout columns={4} variant="text-grid">
              <Stat label="M1 Assessment ready" value={m1} total={total} hint="Assessment phase" />
              <Stat label="M2 Remediation ready" value={m2} total={total} hint="Remediation phase" />
              <Stat
                label="Requirements not met"
                value={data.services.reduce((sum, s) => sum + gapCount(s), 0)}
                hint="Across both phases and all services"
              />
              <Stat
                label="Findings to address"
                value={open.length}
                hint={SEVERITIES.map(sev => `${open.filter(f => f.severity === sev).length} ${sev}`).join(' · ')}
              />
            </ColumnLayout>
            <Box fontSize="heading-m">
              {total
                ? `${m1} of ${plural(total, 'service')} ${m1 === 1 ? 'meets' : 'meet'} every M1 Assessment requirement, and ` +
                  `${m2} ${m2 === 1 ? 'meets' : 'meet'} every M2 Remediation requirement.`
                : 'No next generation Resilience Hub services were found in this account.'}
            </Box>
            {total > 0 && (
              <ColumnLayout columns={2} variant="text-grid">
                <PhaseNames phase="M1 Assessment" ready="m1Ready" />
                <PhaseNames phase="M2 Remediation" ready="m2Ready" />
              </ColumnLayout>
            )}
          </SpaceBetween>
        </Container>
        {total > 0 && <ServicesTable />}
        <ColumnLayout columns={3}>
          <Container fitHeight header={<Header variant="h2" description="Assessment phase. READY when all are met.">M1 Assessment</Header>}>
            <BulletList items={data.requirements['M1 Assessment']} />
          </Container>
          <Container fitHeight header={<Header variant="h2" description="Remediation phase. READY when all are met.">M2 Remediation</Header>}>
            <BulletList items={data.requirements['M2 Remediation']} />
          </Container>
          <Container fitHeight header={<Header variant="h2" description="Next generation Resilience Hub has no score.">Score (RAP-derived)</Header>}>
            <ScoreParts
              parts={[
                ['40', 'RTO/RPO compliance', 'DR targets rated achievable by the latest assessment'],
                ['40', 'Findings remediated', 'Fixes verified by an assessment, weighted HIGH 3, MEDIUM 2, LOW 1'],
                ['20', 'Recovery tests', 'Latest AZ recovery run, and Multi-Region recovery when the policy has Multi-Region targets'],
              ]}
            />
          </Container>
        </ColumnLayout>
        <Callout title="Before you submit the fund request">
          <SpaceBetween size="s">
            <Box variant="p">
              Attach <b>{data.csv}</b> to the fund request, as generated. Don't open and re-save it in Excel: values such as 10/20
              turn into dates. Use the .xlsx copy or this page to read the report.
            </Box>
            <Box variant="p">For the other fund request requirements, refer to your AWS Partner Development Manager (PDM).</Box>
            <Box variant="p" color="text-body-secondary">
              READY is a pre-check, not an approval: the RAP team reviews every fund request.
            </Box>
          </SpaceBetween>
        </Callout>
      </SpaceBetween>
    </ContentLayout>
  );
}

function serviceSummary(s) {
  if (!s.assessed) {
    return `${s.name} has no successful failure mode assessment yet. Run one in Resilience Hub, then generate the report again.`;
  }
  const unmet = items => items.filter(r => r.met === false && r.requirement !== M1_ROW).map(r => r.requirement);
  const m1 = unmet(s.m1Requirements);
  const m2 = unmet(s.m2Requirements);
  if (m1.length) {
    return `${s.name} doesn't meet ${plural(m1.length, 'M1 Assessment requirement')} yet: ${joinAnd(m1)}.`;
  }
  if (m2.length) {
    return `${s.name} meets every M1 Assessment requirement. For M2 Remediation, ${m2.length === 1 ? 'one requirement is' : `${m2.length} requirements are`} not met: ${joinAnd(m2)}.`;
  }
  return `${s.name} meets every M1 Assessment and M2 Remediation requirement.`;
}

function PhaseCard({ title, description, ready, items }) {
  return (
    <Container fitHeight header={<Header variant="h2" description={description} actions={<Verdict ready={ready} />}>{title}</Header>}>
      <SpaceBetween size="m">
        {items.map(r => (
          <Item key={r.requirement} title={r.requirement}>
            <Result met={r.met} actual={r.actual} />
          </Item>
        ))}
      </SpaceBetween>
    </Container>
  );
}

function Details({ service: s }) {
  const findings = s.assessed
    ? [
        { label: 'HIGH findings fixed', value: s.high },
        { label: 'Open findings', value: s.counts.open },
        { label: 'Resolved findings', value: s.counts.resolved },
        { label: 'Resolved, pending re-assessment', value: s.counts.pending },
        { label: 'Irrelevant findings', value: s.counts.irrelevant },
      ]
    : [];
  return (
    <Container header={<Header variant="h2">Service details</Header>}>
      <KeyValuePairs
        columns={4}
        items={[
          { label: 'Application compliance status', value: s.status },
          { label: 'Target RTO', value: s.rto || 'Not set' },
          { label: 'Target RPO', value: s.rpo || 'Not set' },
          { label: 'Rerun needed', value: s.rerun ? <StatusIndicator type="warning">Yes</StatusIndicator> : 'No' },
          { label: 'Recovery test runs', value: s.tests.split('; ').map((line, i) => <div key={i}>{line}</div>) },
          ...findings,
          { label: 'Last assessed', value: s.lastAssessed || 'Not assessed' },
          { label: 'Policy', value: s.policy || 'None' },
          { label: 'Region', value: s.region },
          { label: 'Workload Regions', value: s.workloadRegions || '-' },
          { label: 'Service account', value: s.account },
        ]}
      />
    </Container>
  );
}

function Findings({ title, description, items: all, withState, empty }) {
  const { items, collectionProps, paginationProps } = useCollection(all, { sorting: {}, pagination: { pageSize: PAGE_SIZE } });
  const columns = [
    {
      id: 'severity',
      header: 'Severity',
      cell: f => <Badge color={BADGE[f.severity]}>{f.severity}</Badge>,
      sortingComparator: (a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity),
    },
    { id: 'name', header: 'Finding', cell: f => f.name, sortingField: 'name', isRowHeader: true },
    { id: 'component', header: 'Policy component', cell: f => f.component || '-', sortingField: 'component' },
  ];
  if (withState) {
    columns.push({
      id: 'state',
      header: 'State',
      cell: f => (f.pending ? <StatusIndicator type="pending">Resolved, not yet verified</StatusIndicator> : 'Open'),
    });
  }
  return (
    <Table
      {...collectionProps}
      variant="container"
      wrapLines
      items={items}
      columnDefinitions={columns}
      header={
        <Header variant="h2" counter={`(${all.length})`} description={description}>
          {title}
        </Header>
      }
      pagination={all.length > PAGE_SIZE ? <Pagination {...paginationProps} /> : undefined}
      empty={<Box color="text-body-secondary">{empty}</Box>}
    />
  );
}

function Assessments({ items }) {
  return (
    <Table
      variant="container"
      wrapLines
      items={items}
      trackBy="id"
      header={
        <Header variant="h2" counter={`(${items.length})`} description="Successful failure mode assessments, newest first.">
          Assessments
        </Header>
      }
      columnDefinitions={[
        { id: 'id', header: 'Assessment ID', cell: a => <Box variant="samp">{a.id}</Box>, isRowHeader: true },
        { id: 'ended', header: 'End time', cell: a => a.ended },
        { id: 'status', header: 'Compliance status', cell: a => a.status },
        { id: 'achievability', header: 'Achievability', cell: a => a.achievability.split('; ').map((line, i) => <div key={i}>{line}</div>) },
        { id: 'findings', header: 'Findings', cell: a => a.findings },
      ]}
    />
  );
}

function ServicePage({ service: s, openHelp }) {
  const description = [
    s.region,
    s.policy ? `Policy ${s.policy}` : 'No resilience policy',
    s.lastAssessed ? `Last assessed ${s.lastAssessed}` : 'Not assessed yet',
  ].join(' · ');
  return (
    <ContentLayout
      header={
        <Header variant="h1" info={<InfoLink onFollow={openHelp} />} description={description}>
          {s.name}
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Container>
          <SpaceBetween size="l">
            <ColumnLayout columns={3} variant="text-grid">
              <VerdictStat label="M1 Assessment" ready={s.m1Ready} hint="Assessment phase" />
              <VerdictStat label="M2 Remediation" ready={s.m2Ready} hint="Remediation phase" />
              {s.assessed ? (
                <Stat label="Score (RAP-derived)" value={s.score} total={100} hint={`M2 Remediation needs ${data.minScore}`} />
              ) : (
                <Stat label="Score (RAP-derived)" value="-" hint="After the first successful assessment" />
              )}
            </ColumnLayout>
            <Box fontSize="heading-m">{serviceSummary(s)}</Box>
          </SpaceBetween>
        </Container>
        <ColumnLayout columns={3}>
          <PhaseCard title="M1 Assessment" description="Assessment phase" ready={s.m1Ready} items={s.m1Requirements} />
          <PhaseCard title="M2 Remediation" description="Remediation phase" ready={s.m2Ready} items={s.m2Requirements} />
          <Container
            fitHeight
            header={<Header variant="h2" description="RTO/RPO compliance + findings remediated + recovery tests">Score (RAP-derived)</Header>}
          >
            {s.assessed ? (
              <ScoreParts
                parts={[
                  [`${s.rtoRpo}/40`, 'RTO/RPO compliance', 'DR targets rated achievable by the latest assessment'],
                  [`${s.findingsRemediated}/40`, 'Findings remediated', 'Fixes verified by an assessment, weighted HIGH 3, MEDIUM 2, LOW 1'],
                  [`${s.recoveryTests}/20`, 'Recovery tests', s.tests],
                ]}
              />
            ) : (
              <Box color="text-body-secondary">The score is calculated from the first successful failure mode assessment.</Box>
            )}
          </Container>
        </ColumnLayout>
        <Details service={s} />
        {s.assessed && (
          <Findings
            title="Findings to address"
            description="Open findings, HIGH first. A fix marked resolved counts once a new assessment has verified it."
            items={s.toAddress}
            withState
            empty="No findings to address"
          />
        )}
        {s.assessed && (
          <Findings title="Findings fixed" description="Fixes verified by an assessment." items={s.fixed} empty="No findings fixed yet" />
        )}
        {s.assessed && <Assessments items={s.assessments} />}
      </SpaceBetween>
    </ContentLayout>
  );
}

function Help() {
  return (
    <HelpPanel header={<h2>{TITLE}</h2>} footer={<div>Generated by csv-generator-nextgen.py from next generation AWS Resilience Hub data on {data.generated}.</div>}>
      <p>
        Every service is checked against the RAP requirements of the two milestones: <strong>M1 Assessment</strong>, the
        assessment phase, and <strong>M2 Remediation</strong>, the remediation phase. Each service page lists every requirement with
        its actual value.
      </p>
      <p>
        <strong>READY</strong> means every requirement of the phase is met. It is a pre-check, not an approval: the RAP team reviews
        every fund request.
      </p>
      <h3>Resiliency score (RAP-derived)</h3>
      <p>
        Next generation Resilience Hub has no resiliency score, so the report derives one: RTO/RPO compliance (40) + findings
        remediated (40) + recovery tests (20). Missing or unverified data never raises it.
      </p>
      <h3>Submitting</h3>
      <p>
        Attach the CSV file to the fund request as generated. Don't open and re-save it in Excel: values such as 10/20 turn into
        dates.
      </p>
    </HelpPanel>
  );
}

function useHash() {
  const [hash, setHash] = useState(window.location.hash);
  useEffect(() => {
    const update = () => {
      setHash(window.location.hash);
      window.scrollTo(0, 0);
    };
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);
  return hash;
}

function App() {
  const hash = useHash();
  const [toolsOpen, setToolsOpen] = useState(false);
  const [navigationOpen, setNavigationOpen] = useState(window.innerWidth >= 688);
  const [dark, setDark] = useState(true);
  const [printing, setPrinting] = useState(false);
  const service = data.services.find(s => hash === serviceHref(s));
  const openHelp = () => setToolsOpen(true);

  useEffect(() => {
    document.title = service ? `${service.name} · ${TITLE}` : `${TITLE} · ${data.account} · ${data.generated}`;
  }, [service]);

  useEffect(() => {
    // Dark on screen when chosen; on paper always light, without the side panels
    const mode = () => applyMode(dark ? Mode.Dark : Mode.Light);
    const print = () => {
      applyMode(Mode.Light);
      flushSync(() => {
        setNavigationOpen(false);
        setToolsOpen(false);
        setPrinting(true);
      });
    };
    const printed = () => {
      mode();
      setPrinting(false);
    };
    mode();
    window.addEventListener('beforeprint', print);
    window.addEventListener('afterprint', printed);
    return () => {
      window.removeEventListener('beforeprint', print);
      window.removeEventListener('afterprint', printed);
    };
  }, [dark]);

  const notices = service
    ? service.notes.length
      ? [{ id: 'notes', type: 'warning', header: 'Notes for the RAP review', content: <PlainList items={service.notes} /> }]
      : []
    : overviewNotices();

  return (
    <I18nProvider locale="en" messages={[messages]}>
      <div id="top-nav" style={{ position: 'sticky', top: 0, zIndex: 1002 }}>
        <TopNavigation
          identity={{ href: '#/', title: 'AWS Resilience Acceleration Pilot' }}
          utilities={[
            { type: 'button', iconName: 'status-info', text: 'Help', onClick: openHelp },
            {
              type: 'button',
              iconName: 'light-dark',
              title: dark ? 'Light mode' : 'Dark mode',
              ariaLabel: dark ? 'Switch to light mode' : 'Switch to dark mode',
              onClick: () => setDark(!dark),
            },
            {
              type: 'menu-dropdown',
              iconName: 'file',
              text: TITLE,
              description: `Account ${data.account} · generated ${data.generated}`,
              items: [
                { id: 'account', text: `Account ID: ${data.account}` },
                { id: 'generated', text: `Generated: ${data.generated}` },
                { id: 'source', text: 'Source: next generation AWS Resilience Hub' },
                { id: 'file', text: `File to submit: ${data.csv}` },
              ],
            },
          ]}
        />
      </div>
      <AppLayout
        headerSelector="#top-nav"
        navigationOpen={navigationOpen}
        onNavigationChange={({ detail }) => setNavigationOpen(detail.open)}
        navigation={
          <SideNavigation
            header={{ href: '#/', text: TITLE }}
            activeHref={service ? serviceHref(service) : '#/'}
            items={[
              { type: 'link', text: 'Overview', href: '#/' },
              ...(data.services.length
                ? [
                    {
                      type: 'section',
                      text: 'Services',
                      defaultExpanded: true,
                      items: data.services.map(s => ({ type: 'link', text: s.name, href: serviceHref(s) })),
                    },
                  ]
                : []),
            ]}
          />
        }
        breadcrumbs={<BreadcrumbGroup items={[{ text: TITLE, href: '#/' }, service ? { text: service.name, href: serviceHref(service) } : { text: 'Overview', href: '#/' }]} />}
        notifications={notices.length ? <Flashbar items={notices} /> : undefined}
        tools={<Help />}
        toolsHide={printing}
        toolsOpen={toolsOpen}
        onToolsChange={({ detail }) => setToolsOpen(detail.open)}
        content={service ? <ServicePage key={service.id} service={service} openHelp={openHelp} /> : <Overview openHelp={openHelp} />}
      />
    </I18nProvider>
  );
}

applyMode(Mode.Dark); // before the first paint, so the page never flashes white
createRoot(document.getElementById('root')).render(<App />);
