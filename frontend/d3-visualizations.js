/**
 * D3.js Visualizations for Phase 3
 * Interactive process tree and timeline charts
 */

// ============================================================================
// INTERACTIVE PROCESS TREE (D3.js)
// ============================================================================

function renderProcessTreeD3(processTree) {
  const container = document.getElementById('processes-d3-container');
  if (!container) return;
  
  // Clear previous render
  container.innerHTML = '';
  
  if (!processTree || processTree.length === 0) {
    container.innerHTML = '<p>No process data available</p>';
    return;
  }

  // Parse the hierarchical process data
  const root = buildHierarchy(processTree);
  
  // Set dimensions
  const margin = { top: 20, right: 20, bottom: 20, left: 20 };
  const width = container.clientWidth - margin.left - margin.right;
  const height = Math.max(600, Object.keys(root.children || {}).length * 60);

  // Create SVG
  const svg = d3.select(container)
    .append('svg')
    .attr('width', width + margin.left + margin.right)
    .attr('height', height + margin.top + margin.bottom)
    .style('border', '1px solid #eee')
    .style('background', '#fafafa');

  const g = svg.append('g')
    .attr('transform', `translate(${margin.left},${margin.top})`);

  // Create tree layout
  const tree = d3.tree().size([width, height]);
  const hierarchy = d3.hierarchy(root);
  const links = tree(hierarchy).links();
  const nodes = hierarchy.descendants();

  // Draw links (process relationships)
  g.selectAll('.link')
    .data(links)
    .enter()
    .append('path')
    .attr('class', 'link')
    .attr('d', d3.linkVertical()
      .x(d => d.x)
      .y(d => d.y))
    .style('stroke', '#ccc')
    .style('stroke-width', 2)
    .style('fill', 'none');

  // Draw nodes (processes)
  const nodeGroups = g.selectAll('.node')
    .data(nodes)
    .enter()
    .append('g')
    .attr('class', 'node')
    .attr('transform', d => `translate(${d.x},${d.y})`);

  // Node circles
  nodeGroups.append('circle')
    .attr('r', 6)
    .style('fill', d => {
      if (d.data.risk_score > 70) return '#d32f2f'; // Critical
      if (d.data.risk_score > 40) return '#f57c00'; // High
      if (d.data.risk_score > 20) return '#fbc02d'; // Medium
      return '#388e3c'; // Low
    })
    .style('stroke', '#fff')
    .style('stroke-width', 2)
    .on('mouseover', function(event, d) {
      d3.select(this)
        .transition()
        .duration(200)
        .attr('r', 10);
      
      // Show tooltip
      d3.select(container).selectAll('.tooltip').remove();
      const tooltip = d3.select(container)
        .append('div')
        .attr('class', 'tooltip')
        .style('position', 'absolute')
        .style('background', '#333')
        .style('color', '#fff')
        .style('padding', '10px')
        .style('border-radius', '4px')
        .style('font-size', '12px')
        .style('z-index', '1000')
        .style('pointer-events', 'none');
      
      tooltip.html(`
        <strong>${d.data.name}</strong><br/>
        PID: ${d.data.pid}<br/>
        Risk: ${d.data.risk_score}<br/>
        Threat: ${d.data.threat_level}
      `);
    })
    .on('mouseout', function() {
      d3.select(this)
        .transition()
        .duration(200)
        .attr('r', 6);
      
      d3.select(container).selectAll('.tooltip').remove();
    });

  // Process labels
  nodeGroups.append('text')
    .text(d => {
      const name = d && d.data && d.data.name ? String(d.data.name) : 'process';
      return name.length > 8 ? `${name.substring(0, 8)}` : name;
    })
    .style('font-size', '11px')
    .style('text-anchor', 'middle')
    .style('dy', '0.31em')
    .style('pointer-events', 'none');

  // Add zoom functionality
  const zoom = d3.zoom()
    .on('zoom', (event) => {
      g.attr('transform', event.transform);
    });

  svg.call(zoom);
  
  // Add drag functionality
  nodeGroups.call(d3.drag()
    .on('start', dragStarted)
    .on('drag', dragged)
    .on('end', dragEnded));

  function dragStarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
  }

  function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
  }

  function dragEnded(event, d) {
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
  }
}

function buildHierarchy(processTree) {
  // Normalize multiple inbound shapes into a D3-friendly hierarchy
  const normalizeNode = (node) => {
    if (!node) return null;
    const normalized = {
      name: node.name || 'process',
      pid: node.pid != null ? String(node.pid) : '0',
      risk_score: node.risk_score || node.score || 0,
      threat_level: node.threat_level || node.severity || 'low',
      children: [],
    };
    const rawKids = node.children || [];
    normalized.children = rawKids
      .map(normalizeNode)
      .filter(Boolean);
    return normalized;
  };

  // Handle flat arrays of processes (pid/ppid)
  if (Array.isArray(processTree)) {
    const nodesByPid = {};
    processTree.forEach(p => {
      if (!p) return;
      const pid = p.pid || p.process_id || p.id || '0';
      nodesByPid[pid] = {
        name: p.name || p.command || p.image || `pid ${pid}`,
        pid: String(pid),
        risk_score: p.risk_score || p.score || 0,
        threat_level: p.threat_level || p.severity || 'low',
        _ppid: p.ppid || p.parent_pid || p.parent || '0',
        children: [],
      };
    });

    const roots = [];
    Object.values(nodesByPid).forEach(node => {
      const parent = nodesByPid[node._ppid];
      if (parent) parent.children.push(node);
      else roots.push(node);
    });

    if (roots.length === 1) return normalizeNode(roots[0]);
    return normalizeNode({ name: 'System', pid: '0', children: roots });
  }

  if (typeof processTree === 'string') {
    // Parse ASCII tree format
    const root = {
      name: 'System',
      pid: '0',
      risk_score: 0,
      threat_level: 'low',
      children: {},
    };

    const lines = processTree.split('\n');
    const stack = [root];

    lines.forEach(line => {
      const indent = line.search(/\S/);
      const trimmed = line.trim();
      if (!trimmed) return;

      const match = trimmed.match(/([^\[]+)\[(\d+)\]\s+risk:(\d+)\s+\(([^)]+)\)/);
      if (!match) return;

      const [, name, pid, risk, threat] = match;
      const node = {
        name: name.trim(),
        pid: pid,
        risk_score: parseInt(risk, 10) || 0,
        threat_level: threat,
        children: {},
      };

      while (stack.length > (indent / 2) + 1) {
        stack.pop();
      }

      const parent = stack[stack.length - 1];
      parent.children[pid] = node;
      stack.push(node);
    });

    const collapseObjChildren = (node) => {
      if (node.children && typeof node.children === 'object') {
        node.children = Object.values(node.children).map(collapseObjChildren);
      }
      return node;
    };

    return collapseObjChildren(root);
  }

  // Assume object tree with `children` array (API shape)
  return normalizeNode(processTree);
}

// ============================================================================
// INTERACTIVE TIMELINE CHART (D3.js)
// ============================================================================

function renderTimelineD3(events) {
  const container = document.getElementById('timeline-d3-container');
  if (!container) return;

  container.innerHTML = '';

  if (!events || events.length === 0) {
    container.innerHTML = '<p>No timeline events available</p>';
    return;
  }

  // Parse events
  const data = (events || [])
    .filter(e => e)
    .map(event => {
      const ts = event.timestamp ? new Date(event.timestamp) : new Date();
      const rawDesc = event.description || event.event || event.message || `${event.process || 'process'} event`;
      const desc = rawDesc != null ? String(rawDesc) : '';
      const risk = event.risk_score || event.risk || event.score || 0;
      return {
        timestamp: ts,
        description: desc,
        risk_score: risk,
        type: event.type || 'process'
      };
    })
    .filter(e => e.description !== undefined)
    .sort((a, b) => a.timestamp - b.timestamp);

  // Set dimensions
  const margin = { top: 20, right: 20, bottom: 60, left: 60 };
  const width = container.clientWidth - margin.left - margin.right;
  const height = Math.max(400, Math.min(600, data.length * 30));

  // Create SVG
  const svg = d3.select(container)
    .append('svg')
    .attr('width', width + margin.left + margin.right)
    .attr('height', height + margin.top + margin.bottom)
    .style('border', '1px solid #eee')
    .style('background', '#fafafa');

  const g = svg.append('g')
    .attr('transform', `translate(${margin.left},${margin.top})`);

  // Scales
  const xScale = d3.scaleTime()
    .domain(d3.extent(data, d => d.timestamp))
    .range([0, width]);

  const yScale = d3.scaleBand()
    .domain(d3.range(data.length))
    .range([0, height])
    .padding(0.5);

  // Add timeline line
  g.append('line')
    .attr('x1', xScale(d3.min(data, d => d.timestamp)))
    .attr('x2', xScale(d3.max(data, d => d.timestamp)))
    .attr('y1', height / 2)
    .attr('y2', height / 2)
    .style('stroke', '#ccc')
    .style('stroke-width', 2)
    .style('stroke-dasharray', '5,5');

  // Add points
  g.selectAll('.event-point')
    .data(data)
    .enter()
    .append('circle')
    .attr('class', 'event-point')
    .attr('cx', d => xScale(d.timestamp))
    .attr('cy', (d, i) => yScale(i) + yScale.bandwidth() / 2)
    .attr('r', d => {
      if (d.risk_score > 70) return 8;
      if (d.risk_score > 40) return 6;
      return 4;
    })
    .style('fill', d => {
      if (d.risk_score > 70) return '#d32f2f';
      if (d.risk_score > 40) return '#f57c00';
      if (d.risk_score > 20) return '#fbc02d';
      return '#388e3c';
    })
    .style('stroke', '#fff')
    .style('stroke-width', 2)
    .on('mouseover', function(event, d) {
      d3.select(this)
        .transition()
        .duration(200)
        .attr('r', d => {
          if (d.risk_score > 70) return 12;
          if (d.risk_score > 40) return 10;
          return 8;
        });
    })
    .on('mouseout', function(event, d) {
      d3.select(this)
        .transition()
        .duration(200)
        .attr('r', d => {
          if (d.risk_score > 70) return 8;
          if (d.risk_score > 40) return 6;
          return 4;
        });
    });

  // Add event labels
  g.selectAll('.event-label')
    .data(data)
    .enter()
    .append('text')
    .attr('class', 'event-label')
    .attr('x', d => xScale(d.timestamp))
    .attr('y', (d, i) => yScale(i) + yScale.bandwidth() / 2)
    .attr('dx', 12)
    .attr('dy', '0.31em')
    .style('font-size', '12px')
    .style('fill', '#333')
    .text(d => {
      const desc = d && d.description != null ? String(d.description) : '';
      return desc.length > 40 ? `${desc.slice(0, 40)}...` : desc;
    });

  // Add X-axis (time)
  const xAxis = d3.axisBottom(xScale)
    .tickFormat(d3.timeFormat('%H:%M:%S'));

  g.append('g')
    .attr('transform', `translate(0,${height})`)
    .call(xAxis)
    .style('font-size', '12px');

  // Add X-axis label
  g.append('text')
    .attr('x', width / 2)
    .attr('y', height + 40)
    .style('text-anchor', 'middle')
    .style('font-size', '12px')
    .text('Time');

  // Add Y-axis label
  g.append('text')
    .attr('transform', 'rotate(-90)')
    .attr('y', 0 - margin.left)
    .attr('x', 0 - (height / 2))
    .attr('dy', '1em')
    .style('text-anchor', 'middle')
    .style('font-size', '12px')
    .text('Events');
}

// ============================================================================
// NETWORK GRAPH VISUALIZATION (IOC Relationships)
// ============================================================================

function renderNetworkGraphD3(iocs) {
  const container = document.getElementById('network-graph-container');
  if (!container) return;

  container.innerHTML = '';

  if (!iocs || (!iocs.hashes && !iocs.ips && !iocs.dlls)) {
    container.innerHTML = '<p>No IOC data for network visualization</p>';
    return;
  }

  // Build nodes and links from IOCs
  const nodes = [];
  const links = [];
  const nodeMap = {};

  function addNode(id, label, type) {
    if (!nodeMap[id]) {
      const safeLabel = label ? String(label) : '';
      nodeMap[id] = { id, label: safeLabel.length > 20 ? safeLabel.substring(0, 20) : safeLabel, type };
      nodes.push(nodeMap[id]);
    }
    return nodeMap[id];
  }

  // Add hash nodes
  if (iocs.hashes) {
    iocs.hashes.forEach((hash, i) => {
      const node = addNode(`hash_${i}`, String(hash || '').substring(0, 16), 'hash');
      // Link hashes to central threat node
      links.push({ source: 'threat', target: node.id, type: 'hash' });
    });
  }

  // Add IP nodes
  if (iocs.ips) {
    iocs.ips.forEach((ip, i) => {
      const node = addNode(`ip_${i}`, ip, 'ip');
      links.push({ source: 'threat', target: node.id, type: 'ip' });
    });
  }

  // Add DLL nodes
  if (iocs.dlls) {
    iocs.dlls.forEach((dll, i) => {
      const node = addNode(`dll_${i}`, dll.split('\\').pop(), 'dll');
      links.push({ source: 'threat', target: node.id, type: 'dll' });
    });
  }

  // Add central threat node
  addNode('threat', 'Threat', 'threat');

  // Set dimensions
  const margin = { top: 20, right: 20, bottom: 20, left: 20 };
  const width = container.clientWidth - margin.left - margin.right;
  const height = 500;

  // Create SVG
  const svg = d3.select(container)
    .append('svg')
    .attr('width', width + margin.left + margin.right)
    .attr('height', height + margin.top + margin.bottom)
    .style('border', '1px solid #eee')
    .style('background', '#fafafa');

  const g = svg.append('g')
    .attr('transform', `translate(${margin.left},${margin.top})`);

  // Create force simulation
  const simulation = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links)
      .id(d => d.id)
      .distance(80))
    .force('charge', d3.forceManyBody().strength(-300))
    .force('center', d3.forceCenter(width / 2, height / 2));

  // Draw links
  const linkElements = g.selectAll('.link')
    .data(links)
    .enter()
    .append('line')
    .attr('class', 'link')
    .style('stroke', d => {
      if (d.type === 'hash') return '#d32f2f';
      if (d.type === 'ip') return '#f57c00';
      return '#1976d2';
    })
    .style('stroke-width', 2)
    .style('opacity', 0.6);

  // Draw nodes
  const nodeElements = g.selectAll('.node')
    .data(nodes)
    .enter()
    .append('g')
    .attr('class', 'node')
    .call(d3.drag()
      .on('start', dragStarted)
      .on('drag', dragged)
      .on('end', dragEnded));

  nodeElements.append('circle')
    .attr('r', d => d.type === 'threat' ? 15 : 8)
    .style('fill', d => {
      if (d.type === 'threat') return '#333';
      if (d.type === 'hash') return '#d32f2f';
      if (d.type === 'ip') return '#f57c00';
      return '#1976d2';
    })
    .style('stroke', '#fff')
    .style('stroke-width', 2);

  nodeElements.append('text')
    .text(d => d.label)
    .style('font-size', '11px')
    .style('text-anchor', 'middle')
    .style('dy', '0.31em')
    .style('fill', '#fff')
    .style('pointer-events', 'none');

  // Update positions on simulation tick
  simulation.on('tick', () => {
    linkElements
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);

    nodeElements
      .attr('transform', d => `translate(${d.x},${d.y})`);
  });

  function dragStarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
  }

  function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
  }

  function dragEnded(event, d) {
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
  }
}
