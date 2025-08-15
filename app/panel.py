from jinja2 import Template

TPL = Template("""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SMBSEC SOC Dashboard</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
body{margin:0;background:#0d0d0d;color:#e0e0e0;font-family:'Orbitron',sans-serif;}
header{height:60px;display:flex;align-items:center;justify-content:space-between;padding:0 20px;background:rgba(26,26,26,0.8);backdrop-filter:blur(10px);border-bottom:1px solid rgba(0,255,255,0.2);}
.logo{color:#00ffff;font-weight:700;font-size:20px;}
.clock{font-size:16px;}
.actions i{margin-left:15px;cursor:pointer;color:#00ffff;}
main{display:grid;grid-template-columns:1fr 1.5fr 1fr;grid-template-rows:1fr 200px;grid-template-areas:'left center right''bottom bottom bottom';height:calc(100vh - 60px);}
.left-panel{grid-area:left;padding:20px;border-right:1px solid rgba(0,255,255,0.1);}
.center-panel{grid-area:center;display:flex;align-items:center;justify-content:center;}
.right-panel{grid-area:right;padding:20px;border-left:1px solid rgba(0,255,255,0.1);overflow-y:auto;}
bottom-panel{}
.bottom-panel{grid-area:bottom;display:flex;padding:10px;gap:10px;background:rgba(26,26,26,0.8);backdrop-filter:blur(10px);}
.widget{flex:1;padding:10px;background:rgba(255,255,255,0.05);border:1px solid rgba(0,255,255,0.2);border-radius:8px;}
#incident-feed li{list-style:none;margin-bottom:8px;padding:8px;border-left:4px solid #00ffff;background:rgba(255,255,255,0.05);}
#incident-feed li.low{border-color:#00ff99;}
#incident-feed li.medium{border-color:#ffff00;}
#incident-feed li.high{border-color:#ff0066;}
</style>
</head>
<body>
<header>
<div class="logo">SMBSEC</div>
<div class="clock" id="clock"></div>
<div class="actions">
<i id="alert-icon">⚠️</i>
<i id="settings-icon">⚙️</i>
<i id="user-icon">👤</i>
</div>
</header>
<main>
<div class="left-panel">
<h3>Asset Map</h3>
<div id="asset-map" style="width:100%;height:100%;"></div>
</div>
<div class="center-panel">
<canvas id="status-wheel" width="300" height="300"></canvas>
</div>
<div class="right-panel">
<h3>Incident Feed</h3>
<ul id="incident-feed"></ul>
</div>
<div class="bottom-panel">
<div class="widget"><canvas id="cpu-chart"></canvas></div>
<div class="widget"><canvas id="scan-chart"></canvas></div>
<div class="widget"><canvas id="findings-chart"></canvas></div>
<div class="widget"><canvas id="compliance-chart"></canvas></div>
</div>
</main>
<script>
function updateClock(){
 const d=new Date();
 document.getElementById('clock').textContent=d.toLocaleTimeString();
}
setInterval(updateClock,1000);updateClock();

const statusCtx=document.getElementById('status-wheel').getContext('2d');
const statusChart=new Chart(statusCtx,{type:'doughnut',data:{labels:['Score',''],datasets:[{data:[100,0],backgroundColor:['#00ffff','#1a1a1a'],borderWidth:0}]},options:{cutout:'80%',plugins:{legend:{display:false}},rotation:-90}});

const cpuChart=new Chart(document.getElementById('cpu-chart'),{type:'line',data:{labels:[],datasets:[{label:'CPU %',data:[],borderColor:'#00ffff',tension:0.4}]},options:{scales:{x:{display:false},y:{display:false}},plugins:{legend:{display:false}},animation:false}});
const scanChart=new Chart(document.getElementById('scan-chart'),{type:'doughnut',data:{labels:['Progress',''],datasets:[{data:[0,100],backgroundColor:['#00ff99','#1a1a1a'],borderWidth:0}]},options:{cutout:'70%',plugins:{legend:{display:false}},rotation:-90}});
const findingsChart=new Chart(document.getElementById('findings-chart'),{type:'line',data:{labels:[],datasets:[{label:'Findings',data:[],borderColor:'#ff0066',tension:0.4}]},options:{scales:{x:{display:false},y:{display:false}},plugins:{legend:{display:false}},animation:false}});
const complianceChart=new Chart(document.getElementById('compliance-chart'),{type:'doughnut',data:{labels:['Compliance',''],datasets:[{data:[0,100],backgroundColor:['#ffff00','#1a1a1a'],borderWidth:0}]},options:{cutout:'70%',plugins:{legend:{display:false}},rotation:-90}});

const mapWidth=document.getElementById('asset-map').clientWidth;
const mapHeight=document.getElementById('asset-map').clientHeight;
const svg=d3.select('#asset-map').append('svg').attr('width',mapWidth).attr('height',mapHeight);
const simulation=d3.forceSimulation().force('link',d3.forceLink().id(d=>d.id).distance(80)).force('charge',d3.forceManyBody().strength(-200)).force('center',d3.forceCenter(mapWidth/2,mapHeight/2));
function renderMap(nodes,links){
 svg.selectAll('*').remove();
 const link=svg.append('g').selectAll('line').data(links).enter().append('line').attr('stroke','#00ffff').attr('stroke-width',1).attr('opacity',0.3);
 const node=svg.append('g').selectAll('circle').data(nodes).enter().append('circle').attr('r',8).attr('fill','#00ff99').attr('stroke','#fff').attr('stroke-width',1.5);
 node.append('title').text(d=>d.id);
 simulation.nodes(nodes).on('tick',()=>{
  link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
  node.attr('cx',d=>d.x).attr('cy',d=>d.y);
 });
 simulation.force('link').links(links);
}

let incidents=[];
let filterHigh=false;
function renderIncidents(){
 const feed=document.getElementById('incident-feed');
 feed.innerHTML='';
 incidents.filter(i=>!filterHigh || i.severity==='high').forEach(i=>{
   const li=document.createElement('li');
   li.className=i.severity;
   li.textContent=`${i.severity.toUpperCase()}: ${i.message}`;
   feed.prepend(li);
 });
}
document.getElementById('status-wheel').addEventListener('click',()=>{filterHigh=!filterHigh;renderIncidents();});

const ws=new WebSocket(`ws://${location.host}/ws`);
ws.onmessage=(ev)=>{
 const data=JSON.parse(ev.data);
 statusChart.data.datasets[0].data=[data.score,100-data.score];
 statusChart.update();
 cpuChart.data.labels.push('');
 cpuChart.data.datasets[0].data.push(data.kpis.cpu);
 if(cpuChart.data.datasets[0].data.length>20){cpuChart.data.datasets[0].data.shift();}
 cpuChart.update();
 scanChart.data.datasets[0].data=[data.kpis.scan,100-data.kpis.scan];
 scanChart.update();
 findingsChart.data.labels.push('');
 findingsChart.data.datasets[0].data.push(data.kpis.findings);
 if(findingsChart.data.datasets[0].data.length>20){findingsChart.data.datasets[0].data.shift();}
 findingsChart.update();
 complianceChart.data.datasets[0].data=[data.kpis.compliance,100-data.kpis.compliance];
 complianceChart.update();
 renderMap(data.nodes,data.links);
 incidents.push(data.incident);
 if(incidents.length>50){incidents.shift();}
 renderIncidents();
};
</script>
</body>
</html>
""")

def render_panel(scans:list[dict]) -> str:
    return TPL.render()
